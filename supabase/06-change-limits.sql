-- Nama boleh ditukar sebulan sekali, PIN sehari sekali
alter table public.ranking add column if not exists name_changed_at timestamptz;
alter table public.ranking_keys add column if not exists pin_changed_at timestamptz;
alter table public.ranking_keys alter column pin_changed_at set default now();

create or replace function public.ranking_rename(p_id uuid, p_token text, p_name text)
returns void language plpgsql security definer set search_path = public as $$
declare v_row ranking;
begin
  if not ranking_token_ok(p_id, p_token) then raise exception 'not_allowed'; end if;
  select * into v_row from ranking where id = p_id for update;
  if v_row.name = trim(p_name) then return; end if;
  if v_row.name_changed_at is not null and v_row.name_changed_at > now() - interval '30 days' then
    raise exception 'name_wait:%', to_char((v_row.name_changed_at + interval '30 days') at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"');
  end if;
  update ranking set name = trim(p_name), name_changed_at = now() where id = p_id;
end $$;

create or replace function public.ranking_set_pin(p_id uuid, p_token text, p_pin text)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare v_key ranking_keys;
begin
  if not ranking_token_ok(p_id, p_token) then raise exception 'not_allowed'; end if;
  if coalesce(p_pin, '') !~ '^[0-9]{4}$' or p_pin = '0000' then raise exception 'bad_pin'; end if;
  select * into v_key from ranking_keys where id = p_id for update;
  -- the first PIN can be set any time; after that, once a day
  if v_key.pin_hash is not null and v_key.pin_changed_at is not null and v_key.pin_changed_at > now() - interval '1 day' then
    raise exception 'pin_wait:%', to_char((v_key.pin_changed_at + interval '1 day') at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"');
  end if;
  update ranking_keys
     set pin_hash = crypt(p_pin, gen_salt('bf')), pin_lookup = ranking_pin_lookup(p_pin),
         pin_changed_at = now(), pin_fails = 0, pin_locked_until = null
   where id = p_id;
exception when unique_violation then
  raise exception 'pin_taken';
end $$;

grant execute on function public.ranking_rename(uuid, text, text) to anon, authenticated;
grant execute on function public.ranking_set_pin(uuid, text, text) to anon, authenticated;
notify pgrst, 'reload schema';
