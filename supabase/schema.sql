-- FURA SYSTEM: multi-tenant company approval and vehicle quotas
create extension if not exists pgcrypto;
create table if not exists public.companies (
 id uuid primary key default gen_random_uuid(),
 name text not null,
 owner_user_id uuid not null unique references auth.users(id) on delete cascade,
 status text not null default 'pending' check (status in ('pending','approved','rejected','suspended')),
 vehicle_limit integer not null default 1 check (vehicle_limit between 0 and 10000),
 created_at timestamptz not null default now(),
 reviewed_at timestamptz,
 reviewed_by uuid references auth.users(id)
);
create table if not exists public.vehicles (
 id uuid primary key default gen_random_uuid(),
 company_id uuid not null references public.companies(id) on delete cascade,
 plate text not null,
 created_at timestamptz not null default now(),
 unique(company_id, plate)
);
create table if not exists public.owner_audit (
 id bigint generated always as identity primary key,
 owner_user_id uuid not null references auth.users(id),
 company_id uuid references public.companies(id) on delete set null,
 action text not null,
 details jsonb not null default '{}'::jsonb,
 created_at timestamptz not null default now()
);
create or replace function public.is_owner() returns boolean language sql stable security definer set search_path=public,auth as $$
 select coalesce((auth.jwt()->'app_metadata'->>'role') = 'owner', false)
$$;
create or replace function public.vehicle_limit_guard() returns trigger language plpgsql security definer set search_path=public as $$
declare c public.companies%rowtype; n integer;
begin
 select * into c from public.companies where id=new.company_id for update;
 if not found or c.status <> 'approved' then raise exception 'COMPANY_NOT_APPROVED'; end if;
 select count(*) into n from public.vehicles where company_id=new.company_id;
 if n >= c.vehicle_limit then raise exception 'VEHICLE_LIMIT_REACHED'; end if;
 return new;
end $$;
drop trigger if exists enforce_vehicle_limit on public.vehicles;
create trigger enforce_vehicle_limit before insert on public.vehicles for each row execute function public.vehicle_limit_guard();
alter table public.companies enable row level security;
alter table public.vehicles enable row level security;
alter table public.owner_audit enable row level security;
create policy company_read_self_or_owner on public.companies for select using (owner_user_id=auth.uid() or public.is_owner());
create policy vehicle_read_company on public.vehicles for select using (exists(select 1 from public.companies c where c.id=company_id and (c.owner_user_id=auth.uid() or public.is_owner())));
create policy vehicle_insert_company on public.vehicles for insert with check (exists(select 1 from public.companies c where c.id=company_id and c.owner_user_id=auth.uid() and c.status='approved'));
create policy audit_owner_only on public.owner_audit for select using(public.is_owner());
-- Company rows are created by trusted Netlify function using service-role key, not client-side inserts.
