-- PIN unik untuk ranking ApaJadiClips (0001-9999, satu PIN satu orang)
-- Boleh dijalankan walaupun versi PIN yang lebih awal dah dijalankan.
create extension if not exists pgcrypto with schema extensions;

-- satu akaun boleh ada beberapa browser (setiap satu dapat kunci sendiri)
create table if not exists public.ranking_tokens (
  id uuid not null references public.ranking(id) on delete cascade,
  token_hash bytea not null,
  created_at timestamptz not null default now(),
  primary key (id, token_hash)
);
alter table public.ranking_tokens enable row level security;
revoke all on public.ranking_tokens from anon, authenticated;
insert into public.ranking_tokens (id, token_hash)
  select id, token_hash from public.ranking_keys on conflict do nothing;

alter table public.ranking_keys
  add column if not exists pin_hash text,
  add column if not exists pin_lookup bytea,
  add column if not exists pin_fails integer not null default 0,
  add column if not exists pin_locked_until timestamptz;
create unique index if not exists ranking_keys_pin_lookup on public.ranking_keys (pin_lookup);

-- kunci rahsia untuk semak PIN unik tanpa simpan PIN asal
create table if not exists public.ranking_secret (
  id integer primary key default 1 check (id = 1),
  k bytea not null
);
alter table public.ranking_secret enable row level security;
revoke all on public.ranking_secret from anon, authenticated;
insert into public.ranking_secret (k) values (extensions.gen_random_bytes(32)) on conflict do nothing;

create or replace function public.ranking_pin_lookup(p text)
returns bytea language sql stable security definer set search_path = public, extensions as $$
  select hmac(convert_to(p, 'UTF8'), k, 'sha256') from ranking_secret where id = 1;
$$;
revoke all on function public.ranking_pin_lookup(text) from public, anon, authenticated;

create or replace function public.ranking_token_ok(p_id uuid, p_token text)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from ranking_tokens t
    where t.id = p_id and t.token_hash = sha256(convert_to(coalesce(p_token, ''), 'UTF8')));
$$;
revoke all on function public.ranking_token_ok(uuid, text) from public, anon, authenticated;
drop function if exists public.ranking_pin_weak(text);

-- masuk ranking dengan PIN 0001-9999 yang belum diambil orang
drop function if exists public.ranking_join(text, text, text);
create or replace function public.ranking_join(p_name text, p_username text, p_app text, p_pin text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare v_id uuid; v_token text := gen_random_uuid()::text || gen_random_uuid()::text; v_c text;
begin
  if coalesce(p_pin, '') !~ '^[0-9]{4}$' or p_pin = '0000' then raise exception 'bad_pin'; end if;
  insert into ranking(name, username, app)
  values (trim(p_name), trim(regexp_replace(p_username, '^@+', '')), trim(p_app))
  returning id into v_id;
  insert into ranking_keys(id, token_hash, pin_hash, pin_lookup)
  values (v_id, sha256(convert_to(v_token, 'UTF8')), crypt(p_pin, gen_salt('bf')), ranking_pin_lookup(p_pin));
  insert into ranking_tokens(id, token_hash) values (v_id, sha256(convert_to(v_token, 'UTF8')));
  return json_build_object('id', v_id, 'token', v_token);
exception when unique_violation then
  get stacked diagnostics v_c = constraint_name;
  if v_c = 'ranking_keys_pin_lookup' then raise exception 'pin_taken'; end if;
  raise exception 'username_taken';
end $$;

-- tambah pijakan: cuma naik, paling laju 8 sesaat
create or replace function public.ranking_steps(p_id uuid, p_token text, p_steps integer)
returns integer language plpgsql security definer set search_path = public as $$
declare v_row ranking; v_max integer;
begin
  if not ranking_token_ok(p_id, p_token) then raise exception 'not_allowed'; end if;
  select * into v_row from ranking where id = p_id for update;
  if not found then raise exception 'not_allowed'; end if;
  v_max := v_row.steps + 8 * greatest(1, ceil(extract(epoch from now() - v_row.updated_at)))::int;
  update ranking set steps = least(greatest(v_row.steps, p_steps), v_max, 10000000), updated_at = now()
   where id = p_id returning steps into v_max;
  return v_max;
end $$;

-- tukar nama sahaja
create or replace function public.ranking_rename(p_id uuid, p_token text, p_name text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not ranking_token_ok(p_id, p_token) then raise exception 'not_allowed'; end if;
  update ranking set name = trim(p_name) where id = p_id;
end $$;

-- tetapkan / tukar PIN (dari browser yang dah kenal akaun)
create or replace function public.ranking_set_pin(p_id uuid, p_token text, p_pin text)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  if not ranking_token_ok(p_id, p_token) then raise exception 'not_allowed'; end if;
  if coalesce(p_pin, '') !~ '^[0-9]{4}$' or p_pin = '0000' then raise exception 'bad_pin'; end if;
  update ranking_keys
     set pin_hash = crypt(p_pin, gen_salt('bf')), pin_lookup = ranking_pin_lookup(p_pin),
         pin_fails = 0, pin_locked_until = null
   where id = p_id;
exception when unique_violation then
  raise exception 'pin_taken';
end $$;

-- masuk dari browser lain: username + aplikasi + PIN (5 salah = kunci 15 minit)
create or replace function public.ranking_login(p_username text, p_app text, p_pin text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare v_row ranking; v_key ranking_keys; v_token text := gen_random_uuid()::text || gen_random_uuid()::text;
begin
  select * into v_row from ranking
   where lower(username) = lower(trim(regexp_replace(coalesce(p_username, ''), '^@+', '')))
     and lower(app) = lower(trim(coalesce(p_app, '')));
  if not found then return json_build_object('error', 'wrong_pin'); end if;
  select * into v_key from ranking_keys where id = v_row.id for update;
  if v_key.pin_hash is null then return json_build_object('error', 'no_pin'); end if;
  if v_key.pin_locked_until is not null and v_key.pin_locked_until > now() then
    return json_build_object('error', 'locked');
  end if;
  if coalesce(p_pin, '') !~ '^[0-9]{4}$' or crypt(p_pin, v_key.pin_hash) <> v_key.pin_hash then
    update ranking_keys
       set pin_fails = case when pin_fails + 1 >= 5 then 0 else pin_fails + 1 end,
           pin_locked_until = case when pin_fails + 1 >= 5 then now() + interval '15 minutes' else null end
     where id = v_row.id;
    return json_build_object('error', 'wrong_pin');
  end if;
  update ranking_keys set pin_fails = 0, pin_locked_until = null where id = v_row.id;
  insert into ranking_tokens(id, token_hash) values (v_row.id, sha256(convert_to(v_token, 'UTF8')));
  return json_build_object('id', v_row.id, 'token', v_token, 'name', v_row.name,
    'username', v_row.username, 'app', v_row.app, 'steps', v_row.steps);
end $$;

revoke all on function public.ranking_join(text, text, text, text) from public;
revoke all on function public.ranking_set_pin(uuid, text, text) from public;
revoke all on function public.ranking_login(text, text, text) from public;
grant execute on function public.ranking_join(text, text, text, text) to anon, authenticated;
grant execute on function public.ranking_steps(uuid, text, integer) to anon, authenticated;
grant execute on function public.ranking_rename(uuid, text, text) to anon, authenticated;
grant execute on function public.ranking_set_pin(uuid, text, text) to anon, authenticated;
grant execute on function public.ranking_login(text, text, text) to anon, authenticated;
notify pgrst, 'reload schema';
