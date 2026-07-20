# Adblock Detector — মাল্টি-লেয়ার ডিটেকশন

## ফাইল স্ট্রাকচার

```
adblock-detector/
├── adblock-detector.js     মূল ইঞ্জিন (vanilla JS, ফ্রেমওয়ার্ক-নিরপেক্ষ)
├── ad_728.js                লোকাল bait script (এটাকে নিজের ডোমেইনের রুটে সার্ভ করতে হবে)
├── useAdblockDetector.js     React hook wrapper
├── demo.html                 কাজ করে দেখার জন্য standalone ডেমো
└── README.md
```

## সেটআপ

1. `adblock-detector.js` কে static hosting-এ (GitHub Pages হলে রিপোর রুটে) রাখো।
2. `ad_728.js` কে ঠিক এই নামেই ডোমেইনের রুটে রাখো (path বদলালে
   `CONFIG.localBaitScript` ও বদলাতে হবে)। এই ফাইলনেমটাই গুরুত্বপূর্ণ —
   filter list গুলো `ad_` প্যাটার্ন-ভিত্তিক ফাইল ব্লক করে বলে পরিচিত।
3. HTML-এ লোড করো:
   ```html
   <script src="/adblock-detector.js"></script>
   ```
4. React হলে `useAdblockDetector.js` ইমপোর্ট করো (উদাহরণ ফাইলে দেওয়া আছে)।

## কোন সিগন্যাল কোন লেয়ার ধরে

| সিগন্যাল | কী ধরে | কীভাবে |
|---|---|---|
| `baitElementHidden` / `baitElementRemoved` | Extension (uBlock, ABP), Brave Shields, Firefox Strict Mode | Common ad class/id দিয়ে div বসিয়ে দেখা হয় CSS দিয়ে hide বা DOM থেকে remove হয় কিনা |
| `localScriptBlocked` | Extension network-filter, filename-প্যাটার্ন rule | নিজের ডোমেইনে `ad_728.js` fetch করে দেখা হয় request block হয় কিনা |
| `remoteScriptBlocked` | Filter list (EasyList/uAssets) যেগুলো Google Ads স্ক্রিপ্ট চেনে | `gpt.js`, `adsbygoogle.js` ইত্যাদি known URL fetch করে |
| `dnsProbeBlocked` | Pi-hole, NextDNS, router-level DNS filter, network-wide VPN ad-block | known ad-pixel ডোমেইনে image request পাঠিয়ে load/error/timeout দেখা হয় — DOM-এ কোনো bait লাগে না কারণ DNS-লেভেলে তো পুরো ডোমেইনটাই resolve হয় না |
| `mutationRemoval` (via `watchBaitRemoval`) | দেরিতে কাজ করা lazy/background cosmetic filter | MutationObserver দিয়ে bait element persistent রেখে পরে remove হওয়া observe করা |

## কনফিডেন্স স্কোরিং কেন

একটা মাত্র সিগন্যালে সিদ্ধান্ত নিলে সমস্যা:
- **False positive**: ধীর নেটওয়ার্কে script fetch timeout কে ব্লক ভেবে নেওয়া।
- **False negative**: শুধু bait element চেক করলে DNS-level ব্লকার (যেটা DOM-এ কোনো ছাপ রাখে না) মিস হয়ে যায়।

তাই প্রতিটা সিগন্যালকে ওজন (weight) দিয়ে যোগ করে ০ থেকে ১ এর একটা কনফিডেন্স
স্কোর বানানো হয়েছে (`CONFIG.weights`)। `confidenceThreshold` (ডিফল্ট ০.৪)
এর উপরে গেলে `blocked: true` ধরা হয়। প্রয়োজনমতো থ্রেশহোল্ড টিউন করতে পারো —
কম রাখলে বেশি sensitive (false positive বাড়বে), বেশি রাখলে বেশি strict
(false negative বাড়বে)।

## সীমাবদ্ধতা (গুরুত্বপূর্ণ — সৎভাবে জানিয়ে রাখা ভালো)

- **১০০% নির্ভুল কোনো পদ্ধতি নেই।** অ্যাডব্লকার আর অ্যান্টি-অ্যাডব্লকার একটা
  চলমান আর্মস-রেস — filter list গুলো নিয়মিত bait প্যাটার্ন আপডেট করে, তাই
  bait class name/script name সময় সময় বদলানো লাগবে।
- **DNS-level ব্লক (Pi-hole/NextDNS) সরাসরি "ব্লকার আছে" বলে কনফার্ম করা
  যায় না** — শুধু "এই নির্দিষ্ট known-ad ডোমেইনে request যাচ্ছে না" এটা বলা
  যায়। এটা VPN আউটেজ, ISP সমস্যা, বা সাময়িক নেটওয়ার্ক গ্লিচেও হতে পারে,
  তাই এখানে confidence কম রাখা হয়েছে (single strong signal না)।
- **Stealth-মোড ব্লকার** (AdLock stealth, AdGuard Extra, কিছু 2026-সালের
  advanced blocker) নিজেদের অস্তিত্ব লুকানোর জন্যই ডিজাইন করা — bait
  element কে সরানোর বদলে fake content দিয়ে replace করতে পারে, বা network
  request কে silently 200 OK খালি রেসপন্স দিয়ে সন্তুষ্ট করতে পারে। এসব
  ক্ষেত্রে detection miss হওয়ার সম্ভাবনা থাকে।
- **ব্যবহারকারীর অভিজ্ঞতা নিয়ে চিন্তা রাখা ভালো** — hard-block (পুরো কন্টেন্ট
  আটকে দেওয়া) এর বদলে soft-nudge (demo.html তে যেমন overlay দেখানো হয়েছে,
  কিন্তু "বুঝেছি" দিয়ে বন্ধ করা যায়) approach ইউজার-ফ্রেন্ডলি এবং বেশিরভাগ
  ক্ষেত্রে যথেষ্ট।

## সার্ভার সাইড ডেটা অফ করার লজিক (তোমার আলাদা প্রশ্ন)

তুমি বলেছিলে "detect করলে সার্ভার থেকে data off হবে" সেটা আলাদা হিসাব —
এই detector শুধু ক্লায়েন্ট-সাইড সিগন্যাল দেয় (`result` অবজেক্ট)। এটাকে
সার্ভারে পাঠাতে চাইলে `demo.html`-এ কমেন্ট করা fetch POST অংশটা আনকমেন্ট
করে নিজের এন্ডপয়েন্টে বসাও — কিন্তু মনে রেখো ক্লায়েন্ট-পাঠানো সিগন্যাল
সবসময় স্পুফ করা সম্ভব (ইউজার console থেকে `fetch` override করে ভুয়া
`{blocked:false}` পাঠাতে পারে), তাই যদি সত্যিকারের access-control দরকার
হয় (যেমন paywall), সেটা সবসময় সার্ভার-সাইড ভেরিফিকেশনের সাথে combine
করা উচিত, শুধু ক্লায়েন্ট সিগন্যালের উপর ভরসা না করে।
