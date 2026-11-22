-- VESTIYA Phase 1A — single-file migration (superuser context)
-- Final privilege policy (enforced at end):
--   migrator : KEEPS CREATE on public
--   fn_owner : LOSES CREATE on public/auth at end
--   app      : NEVER has CREATE, no direct EXECUTE on internal functions

-- ================= (0a) Superuser-only: pgcrypto =================
-- Trusted extension installation requires CREATE on DATABASE (not just schema).
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

-- ================= (0b) Roles =================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vestiya_migrator') THEN
    CREATE ROLE vestiya_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vestiya_fn_owner') THEN
    CREATE ROLE vestiya_fn_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE BYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vestiya_app') THEN
    CREATE ROLE vestiya_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT;
  END IF;
END $$;

GRANT vestiya_fn_owner TO vestiya_migrator;

GRANT CREATE ON SCHEMA public TO vestiya_migrator, vestiya_fn_owner;  -- fn_owner temp, revoked at end
GRANT USAGE  ON SCHEMA public TO vestiya_app, vestiya_fn_owner;

-- ================= (0c) Crypto EXECUTE for fn_owner (role now exists) =================
GRANT EXECUTE ON FUNCTION public.hmac(bytea, bytea, text) TO vestiya_fn_owner;
GRANT EXECUTE ON FUNCTION public.digest(bytea, text)       TO vestiya_fn_owner;

SET ROLE vestiya_migrator;

CREATE SCHEMA IF NOT EXISTS auth AUTHORIZATION vestiya_migrator;
REVOKE ALL ON SCHEMA auth FROM PUBLIC, vestiya_app;
GRANT USAGE  ON SCHEMA auth TO vestiya_fn_owner;
GRANT CREATE ON SCHEMA auth TO vestiya_fn_owner;  -- temporary

-- ================= (1) Secret table =================
CREATE TABLE public.vestiya_session_secret (
  id     int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  secret bytea NOT NULL
);
REVOKE ALL ON public.vestiya_session_secret FROM PUBLIC, vestiya_app;
GRANT SELECT ON public.vestiya_session_secret TO vestiya_fn_owner;

-- ================= (2) Crypto wrappers =================
CREATE FUNCTION public.vestiya_hmac_sha256(p_msg bytea, p_key bytea) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SECURITY DEFINER SET search_path = public AS $$
  SELECT public.hmac(p_msg, p_key, 'sha256')
$$;
ALTER FUNCTION public.vestiya_hmac_sha256(bytea, bytea) OWNER TO vestiya_fn_owner;

CREATE FUNCTION public.vestiya_digest_sha256(p_msg bytea) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SECURITY DEFINER SET search_path = public AS $$
  SELECT public.digest(p_msg, 'sha256')
$$;
ALTER FUNCTION public.vestiya_digest_sha256(bytea) OWNER TO vestiya_fn_owner;

-- ================= (3) Session verification =================
CREATE FUNCTION public.vestiya_verify_token(p_token text)
RETURNS TABLE(user_id uuid, workspace_id uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_secret bytea; v_parts text[]; v_msg text; v_sig text; v_exp bigint;
BEGIN
  IF p_token IS NULL OR length(p_token) = 0 THEN RETURN; END IF;
  SELECT secret INTO v_secret FROM public.vestiya_session_secret WHERE id = 1;
  IF v_secret IS NULL THEN
    RAISE EXCEPTION 'session secret not configured' USING ERRCODE = '42501';
  END IF;
  v_parts := string_to_array(p_token, '.');
  IF array_length(v_parts, 1) <> 5 THEN RETURN; END IF;
  v_msg := v_parts[1]||'.'||v_parts[2]||'.'||v_parts[3]||'.'||v_parts[4];
  v_sig := encode(public.vestiya_hmac_sha256(v_msg::bytea, v_secret), 'hex');
  IF length(v_sig) <> length(v_parts[5]) OR v_sig <> lower(v_parts[5]) THEN RETURN; END IF;
  BEGIN v_exp := v_parts[3]::bigint; EXCEPTION WHEN OTHERS THEN RETURN; END;
  IF v_exp < extract(epoch FROM now())::bigint THEN RETURN; END IF;
  BEGIN RETURN QUERY SELECT v_parts[1]::uuid, v_parts[2]::uuid;
  EXCEPTION WHEN OTHERS THEN RETURN; END;
END $$;
ALTER FUNCTION public.vestiya_verify_token(text) OWNER TO vestiya_fn_owner;

CREATE FUNCTION public.vestiya_active_claims()
RETURNS TABLE(user_id uuid, workspace_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT * FROM public.vestiya_verify_token(current_setting('app.session_token', true))
$$;
ALTER FUNCTION public.vestiya_active_claims() OWNER TO vestiya_fn_owner;

CREATE FUNCTION public.vestiya_active_user()
RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT user_id FROM public.vestiya_active_claims() LIMIT 1
$$;
ALTER FUNCTION public.vestiya_active_user() OWNER TO vestiya_fn_owner;

CREATE FUNCTION public.vestiya_active_workspace()
RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT workspace_id FROM public.vestiya_active_claims() LIMIT 1
$$;
ALTER FUNCTION public.vestiya_active_workspace() OWNER TO vestiya_fn_owner;

CREATE FUNCTION public.vestiya_assert_session(p_token text)
RETURNS TABLE(user_id uuid, workspace_id uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE v_uid uuid; v_wid uuid;
BEGIN
  SELECT c.user_id, c.workspace_id INTO v_uid, v_wid
  FROM public.vestiya_verify_token(p_token) c LIMIT 1;
  IF v_uid IS NULL OR v_wid IS NULL THEN
    RAISE EXCEPTION 'invalid or expired session token' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY SELECT v_uid, v_wid;
END $$;
ALTER FUNCTION public.vestiya_assert_session(text) OWNER TO vestiya_fn_owner;

CREATE FUNCTION public.vestiya_bind_verified_session(p_token text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN PERFORM set_config('app.session_token', p_token, true); END $$;
ALTER FUNCTION public.vestiya_bind_verified_session(text) OWNER TO vestiya_fn_owner;

-- ================= (4) Tenancy & users =================
CREATE TABLE public.workspace (
  workspace_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind         text NOT NULL DEFAULT 'personal' CHECK (kind IN ('personal','shared')),
  display_name text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  archived_at  timestamptz
);

CREATE TABLE public.app_user (
  user_id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  external_subject text UNIQUE,
  display_name     text NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  archived_at      timestamptz
);

CREATE TABLE auth.workspace_membership (
  workspace_id uuid NOT NULL REFERENCES public.workspace(workspace_id),
  user_id      uuid NOT NULL REFERENCES public.app_user(user_id),
  role         text NOT NULL CHECK (role IN ('owner','member','viewer')),
  joined_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, user_id)
);
REVOKE ALL ON auth.workspace_membership FROM PUBLIC, vestiya_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.workspace_membership TO vestiya_fn_owner;

CREATE FUNCTION auth.has_role(p_user uuid, p_workspace uuid, p_min text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = auth AS $$
  SELECT p_user IS NOT NULL AND p_workspace IS NOT NULL AND EXISTS (
    SELECT 1 FROM auth.workspace_membership
    WHERE user_id = p_user AND workspace_id = p_workspace
      AND (p_min IS NULL
        OR (p_min='viewer' AND role IN ('owner','member','viewer'))
        OR (p_min='member' AND role IN ('owner','member'))
        OR (p_min='owner'  AND role = 'owner'))
  )
$$;
ALTER FUNCTION auth.has_role(uuid, uuid, text) OWNER TO vestiya_fn_owner;

CREATE FUNCTION public.vestiya_rls_allows_workspace(p_workspace uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, auth AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.vestiya_active_claims() c
    WHERE c.workspace_id = p_workspace
      AND auth.has_role(c.user_id, p_workspace, 'viewer')
  )
$$;
ALTER FUNCTION public.vestiya_rls_allows_workspace(uuid) OWNER TO vestiya_fn_owner;

CREATE FUNCTION public.vestiya_can_view_peer_user(p_target_user uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, auth AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.vestiya_active_claims() c
    JOIN auth.workspace_membership m
      ON m.workspace_id = c.workspace_id AND m.user_id = p_target_user
    WHERE auth.has_role(c.user_id, c.workspace_id, 'viewer')
  )
$$;
ALTER FUNCTION public.vestiya_can_view_peer_user(uuid) OWNER TO vestiya_fn_owner;

CREATE FUNCTION public.vestiya_list_workspace_members()
RETURNS TABLE(workspace_id uuid, user_id uuid, role text, joined_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, auth AS $$
  SELECT m.workspace_id, m.user_id, m.role, m.joined_at
  FROM auth.workspace_membership m
  JOIN public.vestiya_active_claims() c ON m.workspace_id = c.workspace_id
  WHERE auth.has_role(c.user_id, c.workspace_id, 'viewer')
$$;
ALTER FUNCTION public.vestiya_list_workspace_members() OWNER TO vestiya_fn_owner;

CREATE VIEW public.workspace_member WITH (security_invoker = true) AS
SELECT * FROM public.vestiya_list_workspace_members();

-- ================= (5) Item identity, locations, items =================
CREATE TABLE public.item_identity (
  item_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES public.workspace(workspace_id),
  identity_kind text NOT NULL DEFAULT 'physical'
    CHECK (identity_kind IN ('physical','digital','composite')),
  created_at timestamptz NOT NULL DEFAULT now(),
  archived_at timestamptz,
  UNIQUE (workspace_id, item_id)
);

CREATE TABLE public.location (
  location_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES public.workspace(workspace_id),
  parent_id uuid,
  kind text NOT NULL CHECK (kind IN ('site','building','floor','room','closet','shelf','box','other')),
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  archived_at timestamptz,
  CHECK (parent_id IS NULL OR parent_id <> location_id),
  UNIQUE (workspace_id, location_id),
  FOREIGN KEY (workspace_id, parent_id) REFERENCES public.location(workspace_id, location_id)
);
CREATE INDEX location_ws_parent_idx ON public.location(workspace_id, parent_id);

CREATE FUNCTION public.prevent_location_cycle() RETURNS trigger
LANGUAGE plpgsql SET search_path = public AS $$
DECLARE cursor_id uuid := NEW.parent_id; depth int := 0;
BEGIN
  IF NEW.parent_id IS NULL THEN RETURN NEW; END IF;
  PERFORM pg_advisory_xact_lock(hashtext('loc_tree_'||NEW.workspace_id::text));
  WHILE cursor_id IS NOT NULL LOOP
    IF cursor_id = NEW.location_id THEN
      RAISE EXCEPTION 'location cycle detected at %', cursor_id USING ERRCODE = '23P01';
    END IF;
    SELECT parent_id INTO cursor_id FROM public.location
      WHERE location_id = cursor_id AND workspace_id = NEW.workspace_id;
    depth := depth + 1;
    IF depth > 128 THEN RAISE EXCEPTION 'location depth limit exceeded' USING ERRCODE='23P01'; END IF;
  END LOOP;
  RETURN NEW;
END $$;
ALTER FUNCTION public.prevent_location_cycle() OWNER TO vestiya_fn_owner;

CREATE TRIGGER location_no_cycle
  BEFORE INSERT OR UPDATE OF parent_id, workspace_id ON public.location
  FOR EACH ROW EXECUTE FUNCTION public.prevent_location_cycle();

CREATE TABLE public.item (
  item_id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL,
  asset_type text NOT NULL,
  title text NOT NULL,
  attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
  condition_state text NOT NULL DEFAULT 'unknown'
    CHECK (condition_state IN ('new','good','fair','poor','broken','unknown')),
  location_id uuid,
  owner_user_id uuid NOT NULL,
  holder_user_id uuid NOT NULL,
  acquired_at date,
  warranty_until date,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  archived_at timestamptz,
  UNIQUE (workspace_id, item_id),
  FOREIGN KEY (workspace_id, item_id)        REFERENCES public.item_identity(workspace_id, item_id),
  FOREIGN KEY (workspace_id, location_id)    REFERENCES public.location(workspace_id, location_id),
  FOREIGN KEY (workspace_id, owner_user_id)  REFERENCES auth.workspace_membership(workspace_id, user_id),
  FOREIGN KEY (workspace_id, holder_user_id) REFERENCES auth.workspace_membership(workspace_id, user_id)
);
CREATE INDEX item_ws_idx ON public.item(workspace_id);
CREATE INDEX item_attrs_gin ON public.item USING gin (attributes);
CREATE INDEX item_loc_idx ON public.item(location_id);

CREATE FUNCTION public.set_updated_at() RETURNS trigger
LANGUAGE plpgsql SET search_path = public AS $$
BEGIN NEW.updated_at := now(); RETURN NEW; END $$;
ALTER FUNCTION public.set_updated_at() OWNER TO vestiya_fn_owner;

CREATE TRIGGER item_set_updated_at BEFORE UPDATE ON public.item
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TABLE public.item_identifier (
  identifier_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL,
  item_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('qr','barcode','nfc','rfid','serial','visual')),
  value text NOT NULL,
  is_primary boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, kind, value),
  FOREIGN KEY (workspace_id, item_id) REFERENCES public.item(workspace_id, item_id)
);
CREATE INDEX item_identifier_item_idx ON public.item_identifier(item_id);

CREATE TABLE public.item_custody_history (
  custody_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL,
  item_id uuid NOT NULL,
  holder_user_id uuid NOT NULL,
  basis text NOT NULL DEFAULT 'own' CHECK (basis IN ('own','loan','gift','repair','rent')),
  from_ts timestamptz NOT NULL DEFAULT now(),
  to_ts timestamptz,
  CHECK (to_ts IS NULL OR to_ts > from_ts),
  FOREIGN KEY (workspace_id, item_id)        REFERENCES public.item(workspace_id, item_id),
  FOREIGN KEY (workspace_id, holder_user_id) REFERENCES auth.workspace_membership(workspace_id, user_id)
);
CREATE UNIQUE INDEX custody_one_open ON public.item_custody_history(item_id) WHERE to_ts IS NULL;

-- ================= (6) Events, idempotency, outbox =================
CREATE TABLE public.domain_event (
  event_seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_id uuid NOT NULL DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES public.workspace(workspace_id),
  event_type text NOT NULL CHECK (event_type IN
    ('ITEM_CREATED','ITEM_MOVED','ITEM_CONDITION_CHANGED','OWNERSHIP_TRANSFERRED','USAGE_RECORDED')),
  event_version int NOT NULL DEFAULT 1,
  subject_item_id uuid,
  item_seq bigint,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  actor_user_id uuid NOT NULL,
  actor_type text NOT NULL DEFAULT 'user' CHECK (actor_type IN ('user','system','agent')),
  request_id text,
  idempotency_key text,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  reason_ref text,
  source_ref text,
  correlation_id uuid,
  causation_id uuid,
  UNIQUE (event_id),
  UNIQUE (workspace_id, event_id),
  FOREIGN KEY (workspace_id, subject_item_id) REFERENCES public.item_identity(workspace_id, item_id),
  FOREIGN KEY (workspace_id, actor_user_id)   REFERENCES auth.workspace_membership(workspace_id, user_id)
);
CREATE UNIQUE INDEX event_idempotency_uniq ON public.domain_event(workspace_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX event_item_seq_uniq ON public.domain_event(subject_item_id, item_seq)
  WHERE subject_item_id IS NOT NULL;
CREATE INDEX event_subject_idx ON public.domain_event(subject_item_id, item_seq);
CREATE INDEX event_workspace_idx ON public.domain_event(workspace_id, event_seq);

CREATE FUNCTION public.prevent_event_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = public AS $$
BEGIN RAISE EXCEPTION 'domain_event is append-only' USING ERRCODE = '42501'; END $$;
ALTER FUNCTION public.prevent_event_mutation() OWNER TO vestiya_fn_owner;

CREATE TRIGGER event_no_update BEFORE UPDATE ON public.domain_event
  FOR EACH ROW EXECUTE FUNCTION public.prevent_event_mutation();
CREATE TRIGGER event_no_delete BEFORE DELETE ON public.domain_event
  FOR EACH ROW EXECUTE FUNCTION public.prevent_event_mutation();

CREATE TABLE public.operation_idempotency (
  workspace_id uuid NOT NULL REFERENCES public.workspace(workspace_id),
  idempotency_key text NOT NULL,
  operation_name text NOT NULL,
  request_fingerprint text NOT NULL,
  result_item_id uuid,
  result_event_id uuid REFERENCES public.domain_event(event_id),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, idempotency_key)
);

CREATE TABLE public.event_outbox (
  outbox_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  event_type text NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','published','failed')),
  UNIQUE (workspace_id, event_id),
  FOREIGN KEY (workspace_id, event_id) REFERENCES public.domain_event(workspace_id, event_id)
);
CREATE INDEX outbox_pending_idx ON public.event_outbox(status, created_at) WHERE status='pending';

-- ================= (7) RLS =================
DO $$ DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['workspace','app_user','item_identity','location','item',
    'item_identifier','item_custody_history','domain_event','event_outbox','operation_idempotency']
  LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
  END LOOP;
END $$;

CREATE POLICY ws_select ON public.workspace FOR SELECT
  USING (public.vestiya_rls_allows_workspace(workspace_id));
CREATE POLICY user_self ON public.app_user FOR SELECT
  USING (user_id = public.vestiya_active_user());
CREATE POLICY user_peer ON public.app_user FOR SELECT
  USING (public.vestiya_can_view_peer_user(user_id));

DO $$ DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['item_identity','location','item','item_identifier',
    'item_custody_history','domain_event','event_outbox','operation_idempotency']
  LOOP
    EXECUTE format(
      'CREATE POLICY ws_read ON public.%I FOR SELECT USING (public.vestiya_rls_allows_workspace(workspace_id))',
      t);
  END LOOP;
END $$;

-- ================= (8) Idempotency helper & internal emitter =================
CREATE FUNCTION public.vestiya_check_or_reserve_idempotency(
  p_workspace uuid, p_idem text, p_op_name text, p_fingerprint text
) RETURNS TABLE(is_replay boolean, existing_item_id uuid, existing_event_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_rec public.operation_idempotency%ROWTYPE;
BEGIN
  IF p_idem IS NULL THEN RETURN QUERY SELECT false, NULL::uuid, NULL::uuid; RETURN; END IF;
  PERFORM pg_advisory_xact_lock(hashtext('idem_'||p_workspace::text||'_'||p_idem));
  SELECT * INTO v_rec FROM public.operation_idempotency
    WHERE workspace_id = p_workspace AND idempotency_key = p_idem;
  IF FOUND THEN
    IF v_rec.operation_name <> p_op_name OR v_rec.request_fingerprint <> p_fingerprint THEN
      RAISE EXCEPTION 'idempotency key conflict' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT true, v_rec.result_item_id, v_rec.result_event_id;
    RETURN;
  END IF;
  RETURN QUERY SELECT false, NULL::uuid, NULL::uuid;
END $$;
ALTER FUNCTION public.vestiya_check_or_reserve_idempotency(uuid,text,text,text) OWNER TO vestiya_fn_owner;

CREATE FUNCTION public.internal_emit_event(
  p_workspace uuid, p_actor uuid, p_type text, p_subject uuid, p_payload jsonb,
  p_reason text DEFAULT NULL, p_source text DEFAULT NULL,
  p_idem text DEFAULT NULL, p_request text DEFAULT NULL
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, auth AS $$
DECLARE v_next_seq bigint; v_event uuid;
BEGIN
  IF p_subject IS NOT NULL THEN
    PERFORM pg_advisory_xact_lock(hashtext('item_seq_'||p_subject::text));
    PERFORM 1 FROM public.item_identity
      WHERE item_id = p_subject AND workspace_id = p_workspace FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'item not in workspace' USING ERRCODE='42501'; END IF;
    SELECT COALESCE(MAX(item_seq),0)+1 INTO v_next_seq
      FROM public.domain_event WHERE subject_item_id = p_subject;
  END IF;
  INSERT INTO public.domain_event(workspace_id, event_type, subject_item_id, item_seq,
    actor_user_id, payload, reason_ref, source_ref, idempotency_key, request_id)
  VALUES (p_workspace, p_type, p_subject, v_next_seq, p_actor, COALESCE(p_payload,'{}'::jsonb),
    p_reason, p_source, p_idem, p_request)
  RETURNING event_id INTO v_event;
  INSERT INTO public.event_outbox(event_id, workspace_id, event_type, payload)
  VALUES (v_event, p_workspace, p_type, COALESCE(p_payload,'{}'::jsonb));
  RETURN v_event;
END $$;
ALTER FUNCTION public.internal_emit_event(uuid,uuid,text,uuid,jsonb,text,text,text,text) OWNER TO vestiya_fn_owner;

-- ================= (9) Public write functions =================
CREATE FUNCTION public.create_item(
  p_token text, p_asset_type text, p_title text,
  p_attributes jsonb DEFAULT '{}'::jsonb, p_location uuid DEFAULT NULL,
  p_owner uuid DEFAULT NULL, p_qr_value text DEFAULT NULL, p_idem text DEFAULT NULL
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, auth AS $$
DECLARE v_uid uuid; v_wid uuid; v_owner uuid; v_fp text; v_replay boolean; v_ex uuid;
        v_item uuid; v_ev uuid;
BEGIN
  SELECT user_id, workspace_id INTO v_uid, v_wid FROM public.vestiya_assert_session(p_token);
  PERFORM public.vestiya_bind_verified_session(p_token);
  IF NOT auth.has_role(v_uid, v_wid, 'member') THEN
    RAISE EXCEPTION 'write requires member/owner role' USING ERRCODE='42501';
  END IF;
  v_owner := COALESCE(p_owner, v_uid);
  v_fp := encode(public.vestiya_digest_sha256(
    (coalesce(p_asset_type,'')||'|'||coalesce(p_title,'')||'|'||coalesce(p_attributes::text,'')||
     '|'||coalesce(p_location::text,'')||'|'||coalesce(v_owner::text,'')||'|'||coalesce(p_qr_value,''))::bytea),
    'hex');
  SELECT is_replay, existing_item_id INTO v_replay, v_ex
    FROM public.vestiya_check_or_reserve_idempotency(v_wid, p_idem, 'create_item', v_fp);
  IF v_replay THEN RETURN v_ex; END IF;
  IF NOT auth.has_role(v_owner, v_wid, 'viewer') THEN
    RAISE EXCEPTION 'owner must be a workspace member' USING ERRCODE='42501';
  END IF;
  INSERT INTO public.item_identity(workspace_id) VALUES (v_wid) RETURNING item_id INTO v_item;
  INSERT INTO public.item(item_id, workspace_id, asset_type, title, attributes,
    location_id, owner_user_id, holder_user_id)
  VALUES (v_item, v_wid, p_asset_type, p_title, COALESCE(p_attributes,'{}'::jsonb),
    p_location, v_owner, v_uid);
  IF p_qr_value IS NOT NULL THEN
    INSERT INTO public.item_identifier(workspace_id, item_id, kind, value, is_primary)
    VALUES (v_wid, v_item, 'qr', p_qr_value, true);
  END IF;
  INSERT INTO public.item_custody_history(workspace_id, item_id, holder_user_id, basis)
  VALUES (v_wid, v_item, v_uid, 'own');
  v_ev := public.internal_emit_event(v_wid, v_uid, 'ITEM_CREATED', v_item,
    jsonb_build_object('asset_type', p_asset_type, 'title', p_title, 'location_id', p_location),
    NULL, NULL, p_idem, NULL);
  IF p_idem IS NOT NULL THEN
    INSERT INTO public.operation_idempotency(workspace_id, idempotency_key, operation_name,
      request_fingerprint, result_item_id, result_event_id)
    VALUES (v_wid, p_idem, 'create_item', v_fp, v_item, v_ev);
  END IF;
  RETURN v_item;
END $$;
ALTER FUNCTION public.create_item(text,text,text,jsonb,uuid,uuid,text,text) OWNER TO vestiya_fn_owner;

CREATE FUNCTION public.move_item(
  p_token text, p_item uuid, p_to_location uuid,
  p_reason text DEFAULT NULL, p_idem text DEFAULT NULL
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, auth AS $$
DECLARE v_uid uuid; v_wid uuid; v public.item%ROWTYPE; v_fp text;
        v_replay boolean; v_ex uuid; v_ev uuid;
BEGIN
  SELECT user_id, workspace_id INTO v_uid, v_wid FROM public.vestiya_assert_session(p_token);
  PERFORM public.vestiya_bind_verified_session(p_token);
  IF NOT auth.has_role(v_uid, v_wid, 'member') THEN
    RAISE EXCEPTION 'write requires member/owner role' USING ERRCODE='42501';
  END IF;
  v_fp := encode(public.vestiya_digest_sha256(
    (coalesce(p_item::text,'')||'|'||coalesce(p_to_location::text,'')||'|'||coalesce(p_reason,''))::bytea),
    'hex');
  SELECT is_replay, existing_event_id INTO v_replay, v_ex
    FROM public.vestiya_check_or_reserve_idempotency(v_wid, p_idem, 'move_item', v_fp);
  IF v_replay THEN RETURN v_ex; END IF;
  SELECT * INTO v FROM public.item WHERE item_id = p_item FOR UPDATE;
  IF NOT FOUND OR v.workspace_id <> v_wid THEN
    RAISE EXCEPTION 'item not accessible' USING ERRCODE='42501';
  END IF;
  UPDATE public.item SET location_id = p_to_location WHERE item_id = p_item;
  v_ev := public.internal_emit_event(v_wid, v_uid, 'ITEM_MOVED', p_item,
    jsonb_build_object('from', v.location_id, 'to', p_to_location), p_reason, NULL, p_idem, NULL);
  IF p_idem IS NOT NULL THEN
    INSERT INTO public.operation_idempotency(workspace_id, idempotency_key, operation_name,
      request_fingerprint, result_item_id, result_event_id)
    VALUES (v_wid, p_idem, 'move_item', v_fp, p_item, v_ev);
  END IF;
  RETURN v_ev;
END $$;
ALTER FUNCTION public.move_item(text,uuid,uuid,text,text) OWNER TO vestiya_fn_owner;

CREATE FUNCTION public.set_item_condition(
  p_token text, p_item uuid, p_condition text,
  p_reason text DEFAULT NULL, p_idem text DEFAULT NULL
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, auth AS $$
DECLARE v_uid uuid; v_wid uuid; v public.item%ROWTYPE; v_fp text;
        v_replay boolean; v_ex uuid; v_ev uuid;
BEGIN
  SELECT user_id, workspace_id INTO v_uid, v_wid FROM public.vestiya_assert_session(p_token);
  PERFORM public.vestiya_bind_verified_session(p_token);
  IF NOT auth.has_role(v_uid, v_wid, 'member') THEN
    RAISE EXCEPTION 'write requires member/owner role' USING ERRCODE='42501';
  END IF;
  v_fp := encode(public.vestiya_digest_sha256(
    (coalesce(p_item::text,'')||'|'||coalesce(p_condition,'')||'|'||coalesce(p_reason,''))::bytea),
    'hex');
  SELECT is_replay, existing_event_id INTO v_replay, v_ex
    FROM public.vestiya_check_or_reserve_idempotency(v_wid, p_idem, 'set_item_condition', v_fp);
  IF v_replay THEN RETURN v_ex; END IF;
  SELECT * INTO v FROM public.item WHERE item_id = p_item FOR UPDATE;
  IF NOT FOUND OR v.workspace_id <> v_wid THEN
    RAISE EXCEPTION 'item not accessible' USING ERRCODE='42501';
  END IF;
  UPDATE public.item SET condition_state = p_condition WHERE item_id = p_item;
  v_ev := public.internal_emit_event(v_wid, v_uid, 'ITEM_CONDITION_CHANGED', p_item,
    jsonb_build_object('from', v.condition_state, 'to', p_condition),
    p_reason, NULL, p_idem, NULL);
  IF p_idem IS NOT NULL THEN
    INSERT INTO public.operation_idempotency(workspace_id, idempotency_key, operation_name,
      request_fingerprint, result_item_id, result_event_id)
    VALUES (v_wid, p_idem, 'set_item_condition', v_fp, p_item, v_ev);
  END IF;
  RETURN v_ev;
END $$;
ALTER FUNCTION public.set_item_condition(text,uuid,text,text,text) OWNER TO vestiya_fn_owner;

CREATE FUNCTION public.transfer_item_ownership(
  p_token text, p_item uuid, p_to_user uuid,
  p_reason text DEFAULT NULL, p_idem text DEFAULT NULL
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, auth AS $$
DECLARE v_uid uuid; v_wid uuid; v public.item%ROWTYPE; v_fp text;
        v_replay boolean; v_ex uuid; v_ev uuid;
BEGIN
  SELECT user_id, workspace_id INTO v_uid, v_wid FROM public.vestiya_assert_session(p_token);
  PERFORM public.vestiya_bind_verified_session(p_token);
  IF NOT auth.has_role(v_uid, v_wid, 'owner') THEN
    RAISE EXCEPTION 'ownership transfer requires owner role' USING ERRCODE='42501';
  END IF;
  v_fp := encode(public.vestiya_digest_sha256(
    (coalesce(p_item::text,'')||'|'||coalesce(p_to_user::text,'')||'|'||coalesce(p_reason,''))::bytea),
    'hex');
  SELECT is_replay, existing_event_id INTO v_replay, v_ex
    FROM public.vestiya_check_or_reserve_idempotency(v_wid, p_idem, 'transfer_item_ownership', v_fp);
  IF v_replay THEN RETURN v_ex; END IF;
  IF NOT auth.has_role(p_to_user, v_wid, 'member') THEN
    RAISE EXCEPTION 'target owner is not a member' USING ERRCODE='42501';
  END IF;
  SELECT * INTO v FROM public.item WHERE item_id = p_item FOR UPDATE;
  IF NOT FOUND OR v.workspace_id <> v_wid THEN
    RAISE EXCEPTION 'item not accessible' USING ERRCODE='42501';
  END IF;
  IF v.owner_user_id = p_to_user THEN
    RAISE EXCEPTION 'ownership unchanged' USING ERRCODE='22023';
  END IF;
  UPDATE public.item SET owner_user_id = p_to_user WHERE item_id = p_item;
  v_ev := public.internal_emit_event(v_wid, v_uid, 'OWNERSHIP_TRANSFERRED', p_item,
    jsonb_build_object('from', v.owner_user_id, 'to', p_to_user),
    p_reason, NULL, p_idem, NULL);
  IF p_idem IS NOT NULL THEN
    INSERT INTO public.operation_idempotency(workspace_id, idempotency_key, operation_name,
      request_fingerprint, result_item_id, result_event_id)
    VALUES (v_wid, p_idem, 'transfer_item_ownership', v_fp, p_item, v_ev);
  END IF;
  RETURN v_ev;
END $$;
ALTER FUNCTION public.transfer_item_ownership(text,uuid,uuid,text,text) OWNER TO vestiya_fn_owner;

CREATE FUNCTION public.record_usage(
  p_token text, p_item uuid, p_payload jsonb,
  p_source text DEFAULT NULL, p_idem text DEFAULT NULL
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, auth AS $$
DECLARE v_uid uuid; v_wid uuid; v_fp text; v_replay boolean; v_ex uuid; v_ev uuid;
BEGIN
  SELECT user_id, workspace_id INTO v_uid, v_wid FROM public.vestiya_assert_session(p_token);
  PERFORM public.vestiya_bind_verified_session(p_token);
  IF NOT auth.has_role(v_uid, v_wid, 'member') THEN
    RAISE EXCEPTION 'write requires member/owner role' USING ERRCODE='42501';
  END IF;
  v_fp := encode(public.vestiya_digest_sha256(
    (coalesce(p_item::text,'')||'|'||coalesce(p_payload::text,'')||'|'||coalesce(p_source,''))::bytea),
    'hex');
  SELECT is_replay, existing_event_id INTO v_replay, v_ex
    FROM public.vestiya_check_or_reserve_idempotency(v_wid, p_idem, 'record_usage', v_fp);
  IF v_replay THEN RETURN v_ex; END IF;
  v_ev := public.internal_emit_event(v_wid, v_uid, 'USAGE_RECORDED', p_item,
    p_payload, NULL, p_source, p_idem, NULL);
  IF p_idem IS NOT NULL THEN
    INSERT INTO public.operation_idempotency(workspace_id, idempotency_key, operation_name,
      request_fingerprint, result_item_id, result_event_id)
    VALUES (v_wid, p_idem, 'record_usage', v_fp, p_item, v_ev);
  END IF;
  RETURN v_ev;
END $$;
ALTER FUNCTION public.record_usage(text,uuid,jsonb,text,text) OWNER TO vestiya_fn_owner;

-- ================= (10) Table/sequence grants to fn_owner =================
-- (EXECUTE on public.hmac/digest already granted in superuser section (0c).)
GRANT SELECT, INSERT, UPDATE ON
  public.item_identity, public.location, public.item, public.item_identifier,
  public.item_custody_history, public.event_outbox, public.operation_idempotency
  TO vestiya_fn_owner;
GRANT SELECT, INSERT ON public.domain_event TO vestiya_fn_owner;
GRANT SELECT ON public.workspace, public.app_user TO vestiya_fn_owner;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO vestiya_fn_owner;

-- ================= (11) Revoke PUBLIC EXECUTE — project functions only =================
REVOKE EXECUTE ON FUNCTION
  public.vestiya_hmac_sha256(bytea, bytea),
  public.vestiya_digest_sha256(bytea),
  public.vestiya_verify_token(text),
  public.vestiya_active_claims(),
  public.vestiya_active_user(),
  public.vestiya_active_workspace(),
  public.vestiya_assert_session(text),
  public.vestiya_bind_verified_session(text),
  public.vestiya_rls_allows_workspace(uuid),
  public.vestiya_can_view_peer_user(uuid),
  public.vestiya_list_workspace_members(),
  public.vestiya_check_or_reserve_idempotency(uuid, text, text, text),
  public.internal_emit_event(uuid, uuid, text, uuid, jsonb, text, text, text, text),
  public.create_item(text, text, text, jsonb, uuid, uuid, text, text),
  public.move_item(text, uuid, uuid, text, text),
  public.set_item_condition(text, uuid, text, text, text),
  public.transfer_item_ownership(text, uuid, uuid, text, text),
  public.record_usage(text, uuid, jsonb, text, text),
  public.prevent_location_cycle(),
  public.prevent_event_mutation(),
  public.set_updated_at()
  FROM PUBLIC;

REVOKE EXECUTE ON FUNCTION auth.has_role(uuid, uuid, text) FROM PUBLIC;

-- ================= (12) App grants =================
GRANT SELECT ON public.workspace, public.app_user, public.workspace_member,
                public.item_identity, public.location, public.item,
                public.item_identifier, public.item_custody_history,
                public.domain_event, public.event_outbox,
                public.operation_idempotency
  TO vestiya_app;

GRANT EXECUTE ON FUNCTION
  public.vestiya_rls_allows_workspace(uuid),
  public.vestiya_can_view_peer_user(uuid),
  public.vestiya_list_workspace_members(),
  public.vestiya_active_user(),
  public.vestiya_active_workspace(),
  public.create_item(text,text,text,jsonb,uuid,uuid,text,text),
  public.move_item(text,uuid,uuid,text,text),
  public.set_item_condition(text,uuid,text,text,text),
  public.transfer_item_ownership(text,uuid,uuid,text,text),
  public.record_usage(text,uuid,jsonb,text,text)
  TO vestiya_app;

-- ================= (13) Final privilege policy =================
RESET ROLE;

REVOKE CREATE ON SCHEMA public FROM vestiya_fn_owner;
REVOKE CREATE ON SCHEMA auth   FROM vestiya_fn_owner;
-- migrator KEEPS CREATE on public (future migrations).
