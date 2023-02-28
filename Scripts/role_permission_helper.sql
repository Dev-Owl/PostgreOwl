/*
    Optional addtion to the init_postgRest.sql adding in the following features:
    - Allowing you to define a set of rules (strings) like "Can delete record"
    - Rules are connected to (user) roles to show if the user has this rules
    - Short hand function to check if the current user has a given rule
    - Deleting a rule will remove all role connections (cascade delete)

    PLEASE NOTE: Postgreset maps user roles to db roles. If you create a new role you have to run the following:
   
        CREATE ROLE myRole WITH
	        NOLOGIN
	        NOSUPERUSER
	        NOCREATEDB
	        NOCREATEROLE
	        INHERIT
	        NOREPLICATION
	        CONNECTION LIMIT -1;
        GRANT USAGE ON SCHEMA extensions TO myRole;
        GRANT USAGE ON SCHEMA public TO myRole;
        GRANT authenticated to myRole;

    !!!!IMPORTANT!!!!
    Use the permission rule check not only on the client! You must also use it in your server side functions or RLS rules!
*/


-- Main table to track your custom permission rules
CREATE TABLE IF NOT EXISTS auth.permission_rules
(
    "ID" uuid NOT NULL,
    "Rule" text COLLATE pg_catalog."default" NOT NULL,
    CONSTRAINT permission_rules_pkey PRIMARY KEY ("ID"),
    CONSTRAINT "Rule_Is_Unique" UNIQUE ("Rule")
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS auth.permission_rules
    OWNER to postgres;


-- Connecting your rule table to roles
CREATE TABLE IF NOT EXISTS auth.permission_rule_role
(
    "ID" uuid NOT NULL,
    "Rule_Id" uuid NOT NULL,
    "Role" text COLLATE pg_catalog."default" NOT NULL,
    CONSTRAINT permission_rule_role_pkey PRIMARY KEY ("ID"),
    CONSTRAINT "Role_Rule" FOREIGN KEY ("Rule_Id")
        REFERENCES auth.permission_rules ("ID") MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS auth.permission_rule_role
    OWNER to postgres;

-- Helper function to get current role
CREATE OR REPLACE FUNCTION public.current_user_role() RETURNS text
language sql SECURITY DEFINER
  AS $$
		SELECT (current_setting('request.jwt.claims', true)::json->>'role')::text
  
$$;
-- Check if current user has requested permission
CREATE OR REPLACE FUNCTION public.current_user_has_permission(
	permission_rule text)
    RETURNS boolean
    LANGUAGE 'sql'
    COST 100
    STABLE SECURITY DEFINER PARALLEL UNSAFE
AS $BODY$
		
		SELECT COUNT(1) > 0 as HasPermission FROM auth.permission_rule_role
		INNER JOIN auth.permission_rules ON permission_rules."ID" = permission_rule_role."Rule_Id"
		WHERE 
				auth.permission_rules."Rule" = permission_rule 
				AND auth.permission_rule_role."Role" = public.current_user_role()
  
$BODY$;

ALTER FUNCTION public.current_user_has_permission(text)
    OWNER TO postgres;


-- IMPORTANT for every new role you need to run the following, lets assume your new role is called admin:

CREATE ROLE admin WITH
	NOLOGIN
	NOSUPERUSER
	NOCREATEDB
	NOCREATEROLE
	INHERIT
	NOREPLICATION
	CONNECTION LIMIT -1;
GRANT USAGE ON SCHEMA extensions TO admin;
GRANT USAGE ON SCHEMA public TO admin;
GRANT authenticated to admin;
