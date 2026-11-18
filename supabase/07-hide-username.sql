-- Username tak dipaparkan kepada orang awam: website cuma boleh baca nama, aplikasi dan pijakan.
-- Pemilik akaun nampak username sendiri (disimpan dalam telefonnya); developer nampak semua di Supabase.
revoke select on public.ranking from anon, authenticated;
grant select (id, name, app, steps, created_at, updated_at) on public.ranking to anon, authenticated;
notify pgrst, 'reload schema';
