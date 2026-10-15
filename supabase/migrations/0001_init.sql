    -- =========================================
    -- 1. PROFILES (data tambahan pengguna)
    -- =========================================
    create table public.profiles (
    id uuid primary key references auth.users(id) on delete cascade,
    full_name text,
    avatar_url text,
    role text not null default 'user' check (role in ('user', 'super_admin')),
    is_active boolean not null default true,
    created_at timestamptz not null default now()
    );

    -- Otomatis membuat profil saat ada pengguna baru mendaftar
    create or replace function public.handle_new_user()
    returns trigger
    language plpgsql
    security definer set search_path = public
    as $$
    begin
    insert into public.profiles (id, full_name)
    values (new.id, coalesce(new.raw_user_meta_data->>'full_name', ''));
    return new;
    end;
    $$;

    create trigger on_auth_user_created
    after insert on auth.users
    for each row execute function public.handle_new_user();

    -- Fungsi pembantu: cek apakah user yang login adalah Super Admin
    create or replace function public.is_super_admin()
    returns boolean
    language sql
    stable
    security definer set search_path = public
    as $$
    select exists (
        select 1 from public.profiles
        where id = auth.uid() and role = 'super_admin'
    );
    $$;

    -- Mencegah user biasa mengubah role miliknya sendiri
    create or replace function public.protect_profile_role()
    returns trigger
    language plpgsql
    security definer set search_path = public
    as $$
    begin
    if new.role is distinct from old.role and not public.is_super_admin() then
        raise exception 'Hanya Super Admin yang bisa mengubah peran';
    end if;
    return new;
    end;
    $$;

    create trigger trg_protect_profile_role
    before update on public.profiles
    for each row execute function public.protect_profile_role();

    -- =========================================
    -- 2. MASTER DATA
    -- =========================================
    create table public.authors (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    country text,
    created_at timestamptz not null default now()
    );

    create table public.genres (
    id uuid primary key default gen_random_uuid(),
    name text not null unique,
    slug text not null unique
    );

    create table public.subjects (
    id uuid primary key default gen_random_uuid(),
    name text not null unique,
    slug text not null unique
    );

    -- =========================================
    -- 3. BOOKS (koleksi e-book)
    -- =========================================
    create table public.books (
    id uuid primary key default gen_random_uuid(),
    title text not null,
    slug text not null unique,
    author_id uuid references public.authors(id) on delete set null,
    publisher text,
    publication_year int,
    language text not null default 'Indonesia',
    country text,
    genre_id uuid references public.genres(id) on delete set null,
    description text,
    cover_url text,
    file_url text,
    file_type text check (file_type in ('pdf', 'epub')),
    page_count int,
    source_license text not null,
    is_featured boolean not null default false,
    view_count int not null default 0,
    created_by uuid references public.profiles(id) on delete set null,
    created_at timestamptz not null default now(),
    search_vector tsvector generated always as (
        to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(description, ''))
    ) stored
    );

    create index books_search_idx on public.books using gin (search_vector);
    create index books_year_idx on public.books (publication_year);

    create table public.book_subjects (
    book_id uuid references public.books(id) on delete cascade,
    subject_id uuid references public.subjects(id) on delete cascade,
    primary key (book_id, subject_id)
    );

    -- =========================================
    -- 4. INTERAKSI USER
    -- =========================================
    create table public.ratings (
    id uuid primary key default gen_random_uuid(),
    book_id uuid not null references public.books(id) on delete cascade,
    user_id uuid not null references public.profiles(id) on delete cascade,
    score int not null check (score between 1 and 5),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (book_id, user_id)
    );

    create index ratings_book_idx on public.ratings (book_id);

    create table public.comments (
    id uuid primary key default gen_random_uuid(),
    book_id uuid not null references public.books(id) on delete cascade,
    user_id uuid not null references public.profiles(id) on delete cascade,
    content text not null check (char_length(content) between 1 and 1000),
    created_at timestamptz not null default now()
    );

    create index comments_book_idx on public.comments (book_id);

    create table public.reading_lists (
    user_id uuid references public.profiles(id) on delete cascade,
    book_id uuid references public.books(id) on delete cascade,
    created_at timestamptz not null default now(),
    primary key (user_id, book_id)
    );

    create table public.reading_progress (
    user_id uuid references public.profiles(id) on delete cascade,
    book_id uuid references public.books(id) on delete cascade,
    last_location text,
    updated_at timestamptz not null default now(),
    primary key (user_id, book_id)
    );

    -- Fungsi untuk menambah jumlah baca (bisa dipanggil Guest)
    create or replace function public.increment_book_view(p_book_id uuid)
    returns void
    language sql
    security definer set search_path = public
    as $$
    update public.books set view_count = view_count + 1 where id = p_book_id;
    $$;

    grant execute on function public.increment_book_view(uuid) to anon, authenticated;

    -- =========================================
    -- 5. ROW LEVEL SECURITY
    -- =========================================
    alter table public.profiles enable row level security;
    alter table public.authors enable row level security;
    alter table public.genres enable row level security;
    alter table public.subjects enable row level security;
    alter table public.books enable row level security;
    alter table public.book_subjects enable row level security;
    alter table public.ratings enable row level security;
    alter table public.comments enable row level security;
    alter table public.reading_lists enable row level security;
    alter table public.reading_progress enable row level security;

    -- Profiles
    create policy "Profil bisa dilihat semua orang" on public.profiles
    for select using (true);
    create policy "Pengguna ubah profil sendiri, admin ubah semua" on public.profiles
    for update to authenticated
    using (auth.uid() = id or public.is_super_admin())
    with check (auth.uid() = id or public.is_super_admin());
    create policy "Hanya admin hapus profil" on public.profiles
    for delete to authenticated using (public.is_super_admin());

    -- Master data dan buku: semua orang baca, hanya admin tulis
    create policy "Authors dibaca semua" on public.authors for select using (true);
    create policy "Authors dikelola admin" on public.authors
    for all to authenticated using (public.is_super_admin()) with check (public.is_super_admin());

    create policy "Genres dibaca semua" on public.genres for select using (true);
    create policy "Genres dikelola admin" on public.genres
    for all to authenticated using (public.is_super_admin()) with check (public.is_super_admin());

    create policy "Subjects dibaca semua" on public.subjects for select using (true);
    create policy "Subjects dikelola admin" on public.subjects
    for all to authenticated using (public.is_super_admin()) with check (public.is_super_admin());

    create policy "Books dibaca semua" on public.books for select using (true);
    create policy "Books dikelola admin" on public.books
    for all to authenticated using (public.is_super_admin()) with check (public.is_super_admin());

    create policy "Book subjects dibaca semua" on public.book_subjects for select using (true);
    create policy "Book subjects dikelola admin" on public.book_subjects
    for all to authenticated using (public.is_super_admin()) with check (public.is_super_admin());

    -- Ratings
    create policy "Rating dibaca semua" on public.ratings for select using (true);
    create policy "User memberi rating sendiri" on public.ratings
    for insert to authenticated with check (auth.uid() = user_id);
    create policy "User ubah rating sendiri" on public.ratings
    for update to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
    create policy "User hapus rating sendiri, admin hapus semua" on public.ratings
    for delete to authenticated using (auth.uid() = user_id or public.is_super_admin());

    -- Comments
    create policy "Komentar dibaca semua" on public.comments for select using (true);
    create policy "User menulis komentar sendiri" on public.comments
    for insert to authenticated with check (auth.uid() = user_id);
    create policy "User hapus komentar sendiri, admin hapus semua" on public.comments
    for delete to authenticated using (auth.uid() = user_id or public.is_super_admin());

    -- Daftar bacaan dan progres: hanya milik user sendiri
    create policy "User kelola daftar bacaan sendiri" on public.reading_lists
    for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
    create policy "User kelola progres baca sendiri" on public.reading_progress
    for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);