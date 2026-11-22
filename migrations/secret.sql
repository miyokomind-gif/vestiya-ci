INSERT INTO public.vestiya_session_secret(id, secret)
VALUES (1, decode(:'session_secret_hex', 'hex'));
