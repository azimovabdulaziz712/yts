# FURA SYSTEM — server rejimini sozlash (Supabase + Netlify)

Server rejimida firmalar, mashinalar va ma'lumotlar Supabase bazasida saqlanadi, shuning uchun
istalgan kompyuter va telefondan bir xil ko'rinadi.

## Kirish tartibi
1. Firma nomi + firma paroli → **mashinalar oynasi** ochiladi (har bir mashina alohida tugma).
2. Tugmani bosganda mashinaga **parol so'ralmasdan** kiriladi. Mashinalarda parol yo'q.
3. Himoya firma paroli, serverdagi urinishlarni cheklash va serverdagi shifrlashga tayanadi.

## 1. Supabase
1. supabase.com da loyiha oching.
2. SQL Editor → `supabase/schema.sql` faylini to'liq tashlab, **bir marta** bajaring.
3. Project Settings → API: `Project URL` va `service_role` kalitini oling (service_role kalitini hech kimga bermang).

## 2. Kalitlar (`tools/owner-hash.html` — kompyuteringizda oching, serverga yuklamang)
- `OWNER_HASH_1`, `OWNER_HASH_2` — OWNER ikki bosqichli parolining hashlari.
- `SESSION_SECRET` — 64 belgilik tasodifiy kalit.
- `DATA_KEY` — 64 belgilik kalit (ma'lumotlarni serverda shifrlash uchun).
  **DATA_KEY ni yo'qotsangiz ma'lumotlarni tiklab bo'lmaydi. Nusxasini xavfsiz joyda saqlang.**

## 3. Netlify
1. Loyihani GitHub'ga yuklang va Netlify'da "Import from Git" orqali ulang (shunda `@supabase/supabase-js` o'rnatiladi; oddiy zip-drag-and-drop funksiyalar uchun kutubxonani o'rnatmaydi).
2. Site settings → Environment variables:
   `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `SESSION_SECRET`, `DATA_KEY`, `OWNER_HASH_1`, `OWNER_HASH_2`
3. Qayta deploy qiling. Kirish sahifasidagi yozuvda "Server rejimi" ko'rinishi kerak.

## 4. Eski ma'lumotlarni ko'chirish
Eski (lokal) firmalar yaratilgan **o'sha brauzerda** `owner.html` ga kiring → "Serverga ko'chirish".
Eski mashinalarning ma'lumotlari eski mashina paroli bilan shifrlangan edi: ko'chirish paytida har bir mashina uchun
eski parol so'raladi (bekor qilsangiz o'sha mashinaning ma'lumotlari ko'chmaydi). Firmalarning eski parollari o'zgarmaydi.

## Eslatmalar
- Lokal rejimda (server yo'q) ma'lumotlar brauzerda **shifrlanmasdan** saqlanadi va faqat shu brauzerda ko'rinadi.
- Eski lokal mashina ma'lumotlari shifrlangan bo'lsa, mashinaga birinchi kirishda eski parol bir marta so'raladi.
- Firma paroli bilmaydigan odam mashinalarga kira olmaydi; firma parolini kuchli qiling.
- Bu kod haqiqiy Supabase va haqiqiy brauzerda sinalmagan, faqat simulyatsiyada tekshirilgan: birinchi ishga tushirishda hammasini sinab ko'ring.
