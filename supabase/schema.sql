-- FURA SYSTEM: server rejimi (Netlify Functions + Supabase)
-- Bu faylni Supabase → SQL Editor'da BIR MARTA to'liq bajaring.
-- Jadvallarga brauzer to'g'ridan-to'g'ri kira olmaydi: RLS yoqilgan va hech qanday ochiq siyosat yo'q.
-- Faqat Netlify funksiyalari (service_role kaliti bilan) o'qiy va yoza oladi.

create extension if not exists pgcrypto;

create table if not exists public.fura_firms (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  name_norm text not null unique,
  pass_hash text not null,
  pw_enc text,                              -- OWNER ko'rishi uchun shifrlangan parol (kalit faqat OWNER'da)
  vehicle_limit integer not null default 1 check (vehicle_limit between 0 and 10000),
  created_at timestamptz not null default now()
);

create table if not exists public.fura_vehicles (
  id uuid primary key default gen_random_uuid(),
  firm_id uuid not null references public.fura_firms(id) on delete cascade,
  plate text not null unique,
  created_at timestamptz not null default now()
);
create index if not exists fura_vehicles_firm_idx on public.fura_vehicles(firm_id);

-- Mashina ma'lumotlari: qiymatlar server tomonida AES-256-GCM bilan shifrlanib saqlanadi (kalit: DATA_KEY muhit o'zgaruvchisi).
create table if not exists public.fura_kv (
  vehicle_id uuid not null references public.fura_vehicles(id) on delete cascade,
  key text not null,
  value text not null,
  updated_at timestamptz not null default now(),
  primary key (vehicle_id, key)
);

-- Noto'g'ri parol urinishlarini serverda cheklash
create table if not exists public.fura_login_attempts (
  key text primary key,
  fails integer not null default 0,
  level integer not null default 0,
  locked_until timestamptz,
  updated_at timestamptz not null default now()
);

alter table public.fura_firms          enable row level security;
alter table public.fura_vehicles       enable row level security;
alter table public.fura_kv             enable row level security;
alter table public.fura_login_attempts enable row level security;

revoke all on public.fura_firms, public.fura_vehicles, public.fura_kv, public.fura_login_attempts from anon, authenticated;
