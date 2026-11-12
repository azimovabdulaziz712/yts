# FURA SYSTEM — Netlify + Supabase xavfsiz boshqaruv qatlami

## Paket tarkibi
- `supabase/schema.sql` — kompaniyalar, mashinalar, limit va audit jadvallari/RLS.
- `netlify/functions/company-register.mjs` — tasdiq kutayotgan kompaniya yaratish.
- `netlify/functions/owner-review.mjs` — OWNER tasdiqlash/rad etish/bloklash va mashina limitini belgilash.
- `index.html`, `script.js`, `style.css` — avvalgi FURA interfeysi (legacy localStorage login hali mavjud).

## Muhim: productionga chiqarishdan oldin
Bu paket xavfsiz server qatlamining boshlang‘ich integratsiya to‘plami. Eski FURA ilovasining barcha xarajat/reys ma’lumotlari hali Supabase bazasiga ko‘chirilmagan va eski localStorage login avtomatik ravishda Supabase login bilan almashtirilmagan. Shu sababli hozirgi ZIPni darhol haqiqiy mijozlarga sotish uchun tayyor deb hisoblamang. Mijoz ma’lumotlarini himoya qilish uchun keyingi bosqichda barcha ma’lumot jadvallariga `company_id` qo‘shib, RLS siyosatlari bilan ko‘chirish zarur.

## 1. Supabase
1. Supabase loyihasi yarating.
2. SQL Editor’da `supabase/schema.sql` faylini to‘liq bajaring.
3. Authentication → Users orqali o‘zingizning OWNER foydalanuvchingizni yarating.
4. SQL Editor’da OWNER rolini faqat o‘zingizning user UUID’ingizga bering:

```sql
update auth.users
set raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb) || '{"role":"owner"}'::jsonb
where id = 'OWNER-USER-UUID';
```

OWNER uchun kuchli, noyob parol qo‘ying; uni kodga yozmang. App metadata’ni oddiy foydalanuvchi o‘zgartira olmaydi.

## 2. Netlify Environment variables
Netlify → Site configuration → Environment variables:
- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `SUPABASE_SERVICE_ROLE_KEY` (faqat server funksiyalarida; hech qachon brauzerga bermang)
- `ALLOWED_ORIGIN` (saytingizning aniq HTTPS domeni)

So‘ng Netlify’da qayta deploy qiling. `service_role` kalitini hech qachon `index.html`, `script.js` yoki GitHub’ga joylamang.

## 3. API
- `POST /.netlify/functions/company-register` — Supabase Auth bearer token va `{ "name": "Firma nomi" }`.
- `POST /.netlify/functions/owner-review` — OWNER bearer token va `{ "companyId":"UUID", "decision":"approved", "vehicleLimit":12 }`; qaror `rejected` yoki `suspended` ham bo‘lishi mumkin.

Mashina qo‘shish faqat tasdiqlangan kompaniyaga ruxsat etiladi va DB trigger limitdan oshishni bloklaydi.

## 4. OWNER orqali ruxsat berish
SMS yuborilmaydi. Firma ro‘yxatdan o‘tgach, so‘rovi OWNER kabinetidagi “Kompaniya so‘rovlari” ro‘yxatida `pending` holatda ko‘rinadi. “Tasdiqlash” tugmasini bosganda avval firma nomi bilan ruxsat so‘raladi. “Ha” tanlansa, nechta mashina qo‘shishi mumkinligi so‘raladi. Kiritilgan limit tasdiqlash bilan birga saqlanadi; “Yo‘q” tanlansa, firma tasdiqlanmaydi.

## 5. Brauzer himoyasi (yangi)
- **Ma’lumotlar shifrlanadi:** har bir mashinaning ma’lumotlari brauzerda AES-256-GCM bilan shifrlangan holda saqlanadi. Kalit mashina parolidan olinadi va faqat sessiya davomida xotirada turadi. Eski ochiq ma’lumotlar birinchi kirishda avtomatik shifrlanadi.
- **Parolni unutsangiz** ma’lumotni tiklab bo‘lmaydi (kalit paroldan olinadi). Parollarni xavfsiz joyda saqlang.
- **Parol hashlari:** PBKDF2-SHA256, 310 000 aylanish, har akkauntga alohida salt. Eski hashlar to‘g‘ri parol bilan kirilganda avtomatik yangilanadi.
- **OWNER parollarini almashtirish:** `tools/owner-hash.html` faylini kompyuteringizda oching, yangi uzun parolni kiriting va chiqqan qatorni `script.js` boshidagi `OWNER_CREDS` ro‘yxatidagi eski qatorning o‘rniga qo‘ying. Bu fayl saytga yuklanmasin (Netlify uni baribir yashiradi).
- **Cheklov:** barcha ma’lumot hali brauzerning ichida turibdi. Bir nechta qurilmadan kirish va haqiqiy server himoyasi uchun yuqoridagi Supabase bosqichi kerak.

## 6. OWNER kabineti: firma parollari va mashinalar
- Yangi firma parollari OWNER kaliti bilan shifrlab saqlanadi (ochiq matnda emas) va faqat OWNER kabinetida ko‘rinadi. Kalit ikkala OWNER parolidan olinadi, saqlanmaydi.
- OWNER parollarini almashtirsangiz, eski firmalarning ko‘rsatiladigan parollari o‘qilmaydi — kabinetda har bir firmaga yangi parol o‘rnating.
- Mashina raqamini o‘zgartirib bo‘lmaydi (ma’lumot shu raqam va parol bilan shifrlangan): mashinani o‘chirib, yangisini qo‘shing. Mashina o‘chirilsa, uning ma’lumotlari ham o‘chadi.
