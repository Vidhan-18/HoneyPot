-- HoneyPot Platform — Supabase schema
-- Run in Supabase SQL Editor (Dashboard → SQL → New query)

create extension if not exists "pgcrypto";

-- Sessions from honeypot traps (HTTP, SSH, FTP, SMB, DB)
create table if not exists public.honeypot_sessions (
  id uuid primary key default gen_random_uuid(),
  file_name text unique not null,
  client_ip text,
  protocol text,
  service text,
  session_data jsonb not null default '{}'::jsonb,
  location jsonb,
  attacks jsonb default '[]'::jsonb,
  attack_summary jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_honeypot_sessions_created_at
  on public.honeypot_sessions (created_at desc);
create index if not exists idx_honeypot_sessions_client_ip
  on public.honeypot_sessions (client_ip);

-- IOC detections
create table if not exists public.honeypot_iocs (
  id uuid primary key default gen_random_uuid(),
  file_name text unique not null,
  ioc_data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_honeypot_iocs_created_at
  on public.honeypot_iocs (created_at desc);

-- Aggregated log lines
create table if not exists public.honeypot_logs (
  id uuid primary key default gen_random_uuid(),
  source text,
  message text,
  log_entry jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_honeypot_logs_created_at
  on public.honeypot_logs (created_at desc);

-- PCAP metadata (files stay on Oracle VM; store references only)
create table if not exists public.honeypot_pcaps (
  id uuid primary key default gen_random_uuid(),
  file_name text unique not null,
  file_path text,
  size_bytes bigint default 0,
  captured_at timestamptz not null default now()
);

-- Blocked IPs / watchlist
create table if not exists public.blocked_ips (
  ip text primary key,
  blocked_at timestamptz not null default now(),
  reason text default 'manual_block'
);

create table if not exists public.watchlist (
  ip text primary key,
  added_at timestamptz not null default now(),
  reason text default 'manual_watchlist',
  notes text default ''
);

-- Enable Realtime in Supabase Dashboard → Database → Replication:
--   honeypot_sessions, honeypot_logs
-- (Browser dashboard subscribes to INSERT events on these tables.)

-- RLS: service role bypasses; anon reads via policies below
alter table public.honeypot_sessions enable row level security;
alter table public.honeypot_iocs enable row level security;
alter table public.honeypot_logs enable row level security;
alter table public.honeypot_pcaps enable row level security;
alter table public.blocked_ips enable row level security;
alter table public.watchlist enable row level security;

-- Read-only for authenticated users (adjust if you use Supabase Auth later)
create policy "Allow read sessions" on public.honeypot_sessions
  for select using (true);
create policy "Allow read iocs" on public.honeypot_iocs
  for select using (true);
create policy "Allow read logs" on public.honeypot_logs
  for select using (true);
create policy "Allow read pcaps" on public.honeypot_pcaps
  for select using (true);
create policy "Allow read blocked_ips" on public.blocked_ips
  for select using (true);
create policy "Allow read watchlist" on public.watchlist
  for select using (true);

-- Writes from sync service use SUPABASE_SERVICE_ROLE_KEY (bypasses RLS)
