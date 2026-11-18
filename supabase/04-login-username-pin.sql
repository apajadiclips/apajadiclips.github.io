-- Masuk dengan Username + PIN sahaja (PIN sentiasa unik untuk semua aplikasi)
drop function if exists public.ranking_login(text, text, text);
create or replace function public.ranking_login(p_username text, p_pin text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare v_user text := lower(trim(regexp_replace(coalesce(p_username, ''), '^@+', '')));
        v_row ranking; v_token text := gen_random_uuid()::text || gen_random_uuid()::text;
begin
  if not exists (select 1 from ranking where lower(username) = v_user) then
    return json_build_object('error', 'wrong_pin');
  end if;
  if exists (select 1 from ranking r join ranking_keys k on k.id = r.id
             where lower(r.username) = v_user and k.pin_locked_until > now()) then
    return json_build_object('error', 'locked');
  end if;
  if not exists (select 1 from ranking r join ranking_keys k on k.id = r.id
                 where lower(r.username) = v_user and k.pin_hash is not null) then
    return json_build_object('error', 'no_pin');
  end if;
  -- the PIN is unique, so it points at exactly one account; the username must match it
  select r.* into v_row from ranking r join ranking_keys k on k.id = r.id
   where lower(r.username) = v_user
     and coalesce(p_pin, '') ~ '^[0-9]{4}$'
     and k.pin_lookup = ranking_pin_lookup(p_pin)
     and crypt(p_pin, k.pin_hash) = k.pin_hash;
  if not found then
    update ranking_keys k
       set pin_fails = case when k.pin_fails + 1 >= 5 then 0 else k.pin_fails + 1 end,
           pin_locked_until = case when k.pin_fails + 1 >= 5 then now() + interval '15 minutes' else null end
      from ranking r
     where r.id = k.id and lower(r.username) = v_user;
    return json_build_object('error', 'wrong_pin');
  end if;
  update ranking_keys set pin_fails = 0, pin_locked_until = null where id = v_row.id;
  insert into ranking_tokens(id, token_hash) values (v_row.id, sha256(convert_to(v_token, 'UTF8')));
  return json_build_object('id', v_row.id, 'token', v_token, 'name', v_row.name,
    'username', v_row.username, 'app', v_row.app, 'steps', v_row.steps);
end $$;
revoke all on function public.ranking_login(text, text) from public;
grant execute on function public.ranking_login(text, text) to anon, authenticated;
notify pgrst, 'reload schema';
