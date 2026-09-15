# پنل مدیریت کانفیگ VLESS — نسخه Node.js (برای Railway)

این پروژه همون پنل قبلی (Cloudflare Worker) هست که به Node.js تبدیل شده تا مستقیم روی Railway اجرا بشه.

## چی فرق کرده نسبت به نسخه Worker؟

- دیتابیس: به‌جای Cloudflare D1 → از SQLite محلی (فایل `data/app.db`) استفاده می‌کنه
- اتصال VLESS: به‌جای `cloudflare:sockets` → از ماژول `net` نود استفاده می‌کنه
- سرور: به‌جای `fetch` handler ورکر → یه سرور Express معمولی
- باقی همه‌چیز (پنل، API، منطق کاربران و IPها) دقیقاً همونه

## نحوه دیپلوی روی Railway

1. این پوشه رو به یه ریپازیتوری گیت‌هاب جدید پوش کن
2. توی Railway → New Project → Deploy from GitHub repo → همون ریپو رو انتخاب کن
3. توی تب **Variables** این متغیر رو اضافه کن:
   ```
   ADMIN_TOKEN = یه_توکن_قوی_و_طولانی_دلخواه
   ```
   (این همون توکنیه که توی فیلد "Admin Token" پنل وارد می‌کنی، نه پسورد لاگین جدا)
4. برو **Settings → Networking → Generate Domain** تا آدرس عمومی بگیری
5. صبر کن Deploy کامل بشه (تب Deployments رو چک کن)
6. برو به آدرس: `https://دامنه-تو.up.railway.app/panel`
7. توی فیلد "Admin Token" همون مقداری که توی Variables گذاشتی رو بزن و "ذخیره و ورود"

## نکته مهم درباره‌ی دیتابیس روی Railway

SQLite یه فایل محلیه (`data/app.db`). روی Railway، اگه از **Volume** استفاده نکنی، این فایل با هر ریدیپلوی پاک می‌شه و کاربرات از دست می‌رن.

برای جلوگیری از این:
- توی Railway برو **Settings → Volumes**
- یه Volume جدید بساز و Mount Path رو بذار: `/app/data`
- اینجوری دیتابیس دائمی می‌مونه

## اتصال VLESS

آدرس/Host/SNI که توی کلاینت (v2rayNG و غیره) می‌ذاری، همون دامنه Railway‌ته. پورت 443، Security = TLS، Network = WebSocket، Path = `/`.

مسیر ساب‌اسکریپشن: `/sub/<uuid-کاربر>` — دقیقاً مثل قبل.
