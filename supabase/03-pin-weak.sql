-- Tolak PIN yang terlalu senang diteka (jalankan selepas 02-pin.sql)
create or replace function public.ranking_pin_weak(p text)
returns boolean language sql immutable set search_path = public as $$
  select p ~ '^(.)\1{3}$'                                   -- 0000, 1111, ... 9999
      or strpos('0123456789012', p) > 0                     -- 0123, 1234, ... 7890, 8901
      or strpos('9876543210987', p) > 0                     -- 9876, 4321, ... 0987
      or p ~ '^(..)\1$'                                     -- 1212, 6969, 2020
      or p ~ '^(.)\1(.)\2$'                                 -- 1122, 7788
      or p = any (array['2580','0852','1004','0007','1998','1999','2000','2001','2002','2003','2004','2005','2006','2007','2008','2009','2010']);
$$;
revoke all on function public.ranking_pin_weak(text) from public, anon, authenticated;

create or replace function public.ranking_join(p_name text, p_username text, p_app text, p_pin text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare v_id uuid; v_token text := gen_random_uuid()::text || gen_random_uuid()::text;
begin
  if coalesce(p_pin, '') !~ '^[0-9]{4}$' then raise exception 'bad_pin'; end if;
  if ranking_pin_weak(p_pin) then raise exception 'weak_pin'; end if;
  insert into ranking(name, username, app)
  values (trim(p_name), trim(regexp_replace(p_username, '^@+', '')), trim(p_app))
  returning id into v_id;
  insert into ranking_keys(id, token_hash, pin_hash)
  values (v_id, sha256(convert_to(v_token, 'UTF8')), crypt(p_pin, gen_salt('bf')));
  insert into ranking_tokens(id, token_hash) values (v_id, sha256(convert_to(v_token, 'UTF8')));
  return json_build_object('id', v_id, 'token', v_token);
exception when unique_violation then
  raise exception 'username_taken';
end $$;

create or replace function public.ranking_set_pin(p_id uuid, p_token text, p_pin text)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  if not ranking_token_ok(p_id, p_token) then raise exception 'not_allowed'; end if;
  if coalesce(p_pin, '') !~ '^[0-9]{4}$' then raise exception 'bad_pin'; end if;
  if ranking_pin_weak(p_pin) then raise exception 'weak_pin'; end if;
  update ranking_keys set pin_hash = crypt(p_pin, gen_salt('bf')), pin_fails = 0, pin_locked_until = null
   where id = p_id;
end $$;

grant execute on function public.ranking_join(text, text, text, text) to anon, authenticated;
grant execute on function public.ranking_set_pin(uuid, text, text) to anon, authenticated;
notify pgrst, 'reload schema';
