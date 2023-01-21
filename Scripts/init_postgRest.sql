/*
	!! README !!
	Please change the password for jwt_secret and authenticator
	The text between ONLY NEEDED ONCE BY SERVER will throw an error if run twice
*/

-- Set your jwt secret

ALTER DATABASE ratte SET "app.jwt_secret" TO 'super_securesuper_securesuper_secure';

-- !! ONLY NEEDED ONCE BY SERVER !!
-- Create basic roles and connect users
create role authenticator noinherit login password 'super_secure';
grant anon to authenticator;
grant authenticated to authenticator;
-- !! ONLY NEEDED ONCE BY SERVER !!

-- Create schemas 
CREATE SCHEMA IF NOT EXISTS extensions
    AUTHORIZATION postgres;

GRANT USAGE ON SCHEMA extensions TO anon;

GRANT USAGE ON SCHEMA extensions TO authenticated;

GRANT ALL ON SCHEMA extensions TO postgres;


CREATE SCHEMA IF NOT EXISTS public
    AUTHORIZATION postgres;

GRANT USAGE ON SCHEMA public TO anon;

GRANT USAGE ON SCHEMA public TO authenticated;

GRANT ALL ON SCHEMA public TO postgres;

CREATE SCHEMA IF NOT EXISTS auth
    AUTHORIZATION postgres;

GRANT ALL ON SCHEMA auth TO postgres;


-- Enable build in extensions 
CREATE EXTENSION IF NOT EXISTS pgcrypto
    SCHEMA extensions
    VERSION "1.3";
	
CREATE EXTENSION IF NOT EXISTS "uuid-ossp"
    SCHEMA extensions
    VERSION "1.1";

-- Add JWT functions to extensions

set schema 'extensions';

CREATE OR REPLACE FUNCTION url_encode(data bytea) RETURNS text LANGUAGE sql AS $$
    SELECT translate(encode(data, 'base64'), E'+/=\n', '-_');
$$ IMMUTABLE;


CREATE OR REPLACE FUNCTION url_decode(data text) RETURNS bytea LANGUAGE sql AS $$
WITH t AS (SELECT translate(data, '-_', '+/') AS trans),
     rem AS (SELECT length(t.trans) % 4 AS remainder FROM t) -- compute padding size
    SELECT decode(
        t.trans ||
        CASE WHEN rem.remainder > 0
           THEN repeat('=', (4 - rem.remainder))
           ELSE '' END,
    'base64') FROM t, rem;
$$ IMMUTABLE;


CREATE OR REPLACE FUNCTION algorithm_sign(signables text, secret text, algorithm text)
RETURNS text LANGUAGE sql AS $$
WITH
  alg AS (
    SELECT CASE
      WHEN algorithm = 'HS256' THEN 'sha256'
      WHEN algorithm = 'HS384' THEN 'sha384'
      WHEN algorithm = 'HS512' THEN 'sha512'
      ELSE '' END AS id)  -- hmac throws error
SELECT extensions.url_encode(extensions.hmac(signables, secret, alg.id)) FROM alg;
$$ IMMUTABLE;

CREATE OR REPLACE FUNCTION sign(payload json, secret text, algorithm text DEFAULT 'HS256')
RETURNS text LANGUAGE sql AS $$
WITH
  header AS (
    SELECT extensions.url_encode(convert_to('{"alg":"' || algorithm || '","typ":"JWT"}', 'utf8')) AS data
    ),
  payload AS (
    SELECT extensions.url_encode(convert_to(payload::text, 'utf8')) AS data
    ),
  signables AS (
    SELECT header.data || '.' || payload.data AS data FROM header, payload
    )
SELECT
    signables.data || '.' ||
    extensions.algorithm_sign(signables.data, secret, algorithm) FROM signables;
$$ IMMUTABLE;


CREATE OR REPLACE FUNCTION verify(token text, secret text, algorithm text DEFAULT 'HS256')
RETURNS table(header json, payload json, valid boolean) LANGUAGE sql AS $$
  SELECT
    convert_from(extensions.url_decode(r[1]), 'utf8')::json AS header,
    convert_from(extensions.url_decode(r[2]), 'utf8')::json AS payload,
    r[3] = extensions.algorithm_sign(r[1] || '.' || r[2], secret, algorithm) AS valid
  FROM regexp_split_to_array(token, '\.') r;
$$ IMMUTABLE;

-- Helper function to get user details from postgreREST

CREATE OR REPLACE FUNCTION public.current_userid() RETURNS uuid
language sql SECURITY DEFINER
  AS $$
		SELECT (current_setting('request.jwt.claims', true)::json->>'userid')::uuid
  
$$;

-- Create user table

CREATE TABLE IF NOT EXISTS auth.appuser
(
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    name text COLLATE pg_catalog."default" NOT NULL,
    password text COLLATE pg_catalog."default" NOT NULL,
    email text COLLATE pg_catalog."default" NOT NULL,
    role text COLLATE pg_catalog."default" NOT NULL DEFAULT 'authenticated'::text,
    CONSTRAINT appuser_pkey PRIMARY KEY (id),
    CONSTRAINT email UNIQUE (email)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS auth.appuser
    OWNER to postgres;

-- Create auth function for jwt

CREATE TYPE extensions.jwt_token AS (
  token text
);

DROP FUNCTION IF EXISTS public.authenticate(text,text);
CREATE OR REPLACE FUNCTION public.authenticate(username text, password text) RETURNS extensions.jwt_token 
  LANGUAGE plpgsql SECURITY DEFINER
  AS $$
  declare
  	_role text;
	_id text;
  	result extensions.jwt_token;
  begin
  	  SELECT 
	  	  auth.appuser.id,
		  auth.appuser.role
	  FROM 
	  	  auth.appuser 
	  WHERE 
		  auth.appuser.email = username 
		  AND 
		  auth.appuser.password = extensions.crypt($2, auth.appuser.password)
	  into _id,_role;
	  
	  if _role is null then
	    raise invalid_password using message = 'invalid user or password';
	  end if;
		  
	  SELECT extensions.sign(
		row_to_json(r), current_setting('app.jwt_secret')
	  ) AS token
	  FROM (
		SELECT
		  _role as role,
		  _id as userid,
		  extract(epoch from now())::integer + 300 AS exp
	  ) r INTO result;
	  return result;
   end;
$$;
grant execute on function public.authenticate(text,text) to anon;

-- Example insert for a user
--INSERT INTO auth.appuser (name,email,password) VALUES('example','example@example.com',extensions.crypt('example', extensions.gen_salt('bf')));
	

