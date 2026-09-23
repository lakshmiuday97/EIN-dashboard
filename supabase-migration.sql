-- =========================================================
-- E.I.N. NODE COORDINATE MANAGEMENT & AUDIT TRAIL MIGRATION
-- =========================================================

-- 1. Create Location History Audit Table
CREATE TABLE IF NOT EXISTS public.node_location_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id VARCHAR(50) NOT NULL,
    old_latitude DOUBLE PRECISION NOT NULL,
    old_longitude DOUBLE PRECISION NOT NULL,
    new_latitude DOUBLE PRECISION NOT NULL,
    new_longitude DOUBLE PRECISION NOT NULL,
    changed_by UUID REFERENCES auth.users(id),
    changed_at TIMESTAMPTZ DEFAULT NOW(),
    reason TEXT,
    location_source VARCHAR(50) DEFAULT 'manual'
);

-- 2. Enable Row Level Security (RLS)
ALTER TABLE public.nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.node_location_history ENABLE ROW LEVEL SECURITY;

-- 3. Drop Legacy Permissive / Anon Policies if present
DROP POLICY IF EXISTS "Allow read access to authenticated and anon users" ON public.node_location_history;
DROP POLICY IF EXISTS "Allow insert access to authenticated and anon users" ON public.node_location_history;
DROP POLICY IF EXISTS "Allow update access to nodes" ON public.nodes;

-- 4. Create Strict Authenticated RLS Policies
-- Nodes Table Policies
CREATE POLICY "Authenticated users can read nodes"
ON public.nodes FOR SELECT
TO authenticated
USING (true);

CREATE POLICY "Authenticated users can update nodes"
ON public.nodes FOR UPDATE
TO authenticated
USING (auth.uid() IS NOT NULL)
WITH CHECK (auth.uid() IS NOT NULL);

-- Node Location History Policies
CREATE POLICY "Authenticated users can read location history"
ON public.node_location_history FOR SELECT
TO authenticated
USING (true);

CREATE POLICY "Authenticated users can insert location history"
ON public.node_location_history FOR INSERT
TO authenticated
WITH CHECK (auth.uid() IS NOT NULL);

-- 5. Atomic PL/pgSQL Function: update_node_location
CREATE OR REPLACE FUNCTION public.update_node_location(
    p_node_id VARCHAR,
    p_new_latitude DOUBLE PRECISION,
    p_new_longitude DOUBLE PRECISION,
    p_location_source VARCHAR DEFAULT 'manual',
    p_reason TEXT DEFAULT NULL,
    p_expected_updated_at TIMESTAMPTZ DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_user_id UUID;
    v_old_lat DOUBLE PRECISION;
    v_old_lng DOUBLE PRECISION;
    v_current_updated_at TIMESTAMPTZ;
    v_updated_node RECORD;
    v_history_id UUID;
BEGIN
    -- 1. Authorization check
    v_user_id := auth.uid();
    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'Authentication required for coordinate modification.' USING ERRCODE = '42501';
    END IF;

    -- 2. Row lock and current state fetch
    SELECT latitude, longitude, updated_at
    INTO v_old_lat, v_old_lng, v_current_updated_at
    FROM public.nodes
    WHERE node_id = p_node_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Node with ID % not found.', p_node_id USING ERRCODE = 'P0002';
    END IF;

    -- 3. Database-level stale edit prevention
    IF p_expected_updated_at IS NOT NULL AND v_current_updated_at <> p_expected_updated_at THEN
        RAISE EXCEPTION 'Conflict: Node location was modified by another user since loading. Please refresh and retry.' USING ERRCODE = 'P0001';
    END IF;

    -- 4. Atomic Node Location Update
    UPDATE public.nodes
    SET 
        latitude = p_new_latitude,
        longitude = p_new_longitude,
        updated_at = NOW()
    WHERE node_id = p_node_id
    RETURNING * INTO v_updated_node;

    -- 5. Atomic Location Audit Entry Insert
    INSERT INTO public.node_location_history (
        node_id,
        old_latitude,
        old_longitude,
        new_latitude,
        new_longitude,
        changed_by,
        changed_at,
        reason,
        location_source
    ) VALUES (
        p_node_id,
        v_old_lat,
        v_old_lng,
        p_new_latitude,
        p_new_longitude,
        v_user_id,
        NOW(),
        p_reason,
        COALESCE(p_location_source, 'manual')
    )
    RETURNING id INTO v_history_id;

    -- 6. Return structured result
    RETURN jsonb_build_object(
        'success', true,
        'node_id', p_node_id,
        'new_latitude', p_new_latitude,
        'new_longitude', p_new_longitude,
        'history_id', v_history_id,
        'updated_at', v_updated_node.updated_at
    );
END;
$$;
