/**
 * adblock-detector.js
 * -----------------------------------------------------------------------
 * Multi-technique ad-blocker detection engine.
 *
 * কেন multi-technique?
 *   কোনো একটা কৌশল দিয়ে সব ধরনের ব্লকার (extension, browser built-in,
 *   DNS-level) ধরা সম্ভব না। তাই এখানে কয়েকটা independent সিগন্যাল নেওয়া
 *   হয়, প্রতিটাকে ওজন (weight) দেওয়া হয়, আর শেষে একটা confidence score
 *   বের করে সিদ্ধান্ত নেওয়া হয়। এতে false positive/negative কমে।
 *
 * টেকনিক লিস্ট:
 *   1. Bait DOM element      -> extension/browser cosmetic filtering ধরে
 *   2. Bait network request  -> extension/browser network filtering ধরে
 *   3. Known ad script URL   -> filter list (EasyList ইত্যাদি) ধরে
 *   4. DNS self-check API    -> dns.adguard.com/test.json দিয়ে নির্দিষ্ট
 *                                 DNS resolver active কিনা (extension
 *                                 থেকে independent সিগন্যাল)
 *   5. MutationObserver      -> পরে bait remove হলে (lazy blockers) ধরে
 *
 * ব্যবহার:
 *   const result = await AdblockDetector.detect();
 *   console.log(result.blocked, result.confidence, result.signals);
 * -----------------------------------------------------------------------
 */

(function (global) {
  'use strict';

  // -----------------------------------------------------------------------
  // কনফিগারেশন
  // -----------------------------------------------------------------------
  const CONFIG = {
    // bait div-এ common ad-related class/id বসানো হয় যাতে filter list
    // (EasyList/uBlock rules) সেগুলোকে cosmetic filtering দিয়ে hide করে
    baitClassNames: [
      'ad', 'ads', 'adsbox', 'ad-placement', 'ad-placeholder',
      'ad-banner', 'adbadge', 'BannerAd', 'banner-ads',
      'sponsored-post', 'text-ad', 'textAd', 'text_ad', 'google-ad',
    ],

    // known ad-script filenames — filter lists এদের block করে বলে পরিচিত
    baitScriptUrls: [
      'https://www.googletagservices.com/tag/js/gpt.js',
      'https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js',
      'https://securepubads.g.doubleclick.net/tag/js/gpt.js',
    ],

    // নিজের ডোমেইনে একটা obviously-ad-named ফাইল রাখলে ভালো, কারণ
    // generic filter list গুলো filename pattern দিয়েও ব্লক করে
    // (নিচের ইনস্ট্রাকশন দ্রষ্টব্য — ad_728.js ফাইলটা বানিয়ে দিতে হবে)
    localBaitScript: '/ad_728.js',

    // ⚠️ পুরনো approach বাদ: googlesyndication/doubleclick pixel probe
    // extension filter list দিয়েও ব্লক হয়, তাই DNS-level আলাদা করা যেত না।
    // এখন provider-নির্দিষ্ট "self-check" endpoint ব্যবহার হচ্ছে যা
    // filter list এর টার্গেট না (তাই extension independent), বরং সরাসরি
    // বলে দেয় client সেই DNS resolver দিয়ে resolve হচ্ছে কিনা।
    dnsSelfCheckProviders: [
      {
        name: 'AdGuard DNS',
        url: 'https://dns.adguard.com/test.json',
        parse: (data) => {
          if (!data || typeof data !== 'object') return false;
          if (typeof data.status === 'boolean') return data.status;
          if (typeof data.status === 'string') {
            return /running|active|true|ok/i.test(data.status);
          }
          return Boolean(data.isUsingDns || data.adguard || data.protected);
        },
      },
      // NextDNS যোগ করতে চাইলে:
      // { name: 'NextDNS', url: 'https://test.nextdns.io', parse: (d) => d && d.status === 'ok' }
    ],

    timeouts: {
      baitCheckMs: 120,      // bait element রেন্ডারের পর কতক্ষণ ওয়েট করবো
      scriptFetchMs: 1500,   // remote script fetch টাইমআউট
      dnsProbeMs: 1800,      // DNS probe টাইমআউট (সাধারণ network এর চেয়ে বেশি সময় দেওয়া, কারণ sinkhole হলে TCP hang করতে পারে)
      overallMs: 3000,       // পুরো detect() এর হার্ড ক্যাপ
    },

    // প্রতিটা সিগন্যালের ওজন — যোগফল দিয়ে ০-১ কনফিডেন্স স্কোর হয়
    weights: {
      baitElementHidden: 0.35,
      baitElementRemoved: 0.35,
      localScriptBlocked: 0.25,
      remoteScriptBlocked: 0.15,
      dnsProbeBlocked: 0.20,
      mutationRemoval: 0.30,
    },

    // এই থ্রেশহোল্ডের উপরে গেলে "blocked: true" ধরা হবে
    confidenceThreshold: 0.4,
  };

  // -----------------------------------------------------------------------
  // ইউটিলিটি
  // -----------------------------------------------------------------------
  function withTimeout(promise, ms, fallbackValue) {
    return Promise.race([
      promise,
      new Promise((resolve) => setTimeout(() => resolve(fallbackValue), ms)),
    ]);
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  // -----------------------------------------------------------------------
  // টেকনিক ১: Bait DOM Element
  // -----------------------------------------------------------------------
  // একটা div তৈরি করে body-তে বসিয়ে দেই, common ad class/id দিয়ে।
  // cosmetic filter (uBlock, ABP, Brave Shields ইত্যাদি) সাধারণত এগুলো
  // display:none করে দেয় অথবা DOM থেকেই সরিয়ে দেয়।
  function createBaitElement() {
    const bait = document.createElement('div');
    bait.setAttribute('class', CONFIG.baitClassNames.join(' '));
    bait.setAttribute('id', 'ad-detector-bait-' + Math.random().toString(36).slice(2));

    // ইনলাইন স্টাইল — কিছু filter list ইনলাইন স্টাইল প্যাটার্নও টার্গেট করে
    bait.style.cssText = [
      'position:absolute',
      'top:-9999px',
      'left:-9999px',
      'width:1px',
      'height:1px',
      'display:block',
    ].join(';');

    // ভেতরে কিছু dummy content — কিছু blocker খালি div ইগনোর করতে পারে
    bait.innerHTML = '&nbsp;';

    document.body.appendChild(bait);
    return bait;
  }

  async function checkBaitElement() {
    const bait = createBaitElement();

    // filter apply হতে সামান্য সময় লাগে (browser layout/style recalculation)
    await sleep(CONFIG.timeouts.baitCheckMs);

    const stillInDom = document.body.contains(bait);
    let hidden = false;

    if (stillInDom) {
      const style = window.getComputedStyle(bait);
      hidden =
        style.display === 'none' ||
        style.visibility === 'hidden' ||
        bait.offsetHeight === 0 ||
        bait.offsetParent === null;
    }

    const removed = !stillInDom;

    // পরিষ্কার করি (removed না হলে)
    if (stillInDom) {
      bait.remove();
    }

    return { hidden, removed };
  }

  // -----------------------------------------------------------------------
  // টেকনিক ২ ও ৩: Script fetch (local bait ফাইল + known remote ad script)
  // -----------------------------------------------------------------------
  // fetch() ব্যবহার করছি bare script tag এর বদলে, কারণ:
  //  - network-level ব্লক হলে fetch() promise reject করে (TypeError)
  //  - script-tag onerror অনেক সময় ব্লকারের ইন্টারনাল noop script দিয়ে
  //    "silently succeed" দেখায়, fetch এ সেটা কম হয়
  async function probeUrlBlocked(url, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      // no-cors রাখছি cross-origin script এর জন্য যাতে CORS এর কারণে
      // false-positive না হয়; আমরা শুধু "request গেল কিনা" সেটা দেখছি,
      // response content নয়।
      await fetch(url, {
        method: 'GET',
        mode: 'no-cors',
        cache: 'no-store',
        signal: controller.signal,
      });
      clearTimeout(timer);
      return false; // request সফল হয়েছে -> ব্লক হয়নি
    } catch (err) {
      clearTimeout(timer);
      // AbortError মানে টাইমআউট (হতে পারে ধীরগতির নেটওয়ার্ক, ব্লকার না)
      // কিন্তু DNS-sinkhole হলে সাধারণত connection hang করে timeout এ পড়ে,
      // তাই টাইমআউটকেও একটা দুর্বল সিগন্যাল হিসেবে ট্রিট করছি (কলার সাইডে)
      return err.name === 'AbortError' ? 'timeout' : true;
    }
  }

  async function checkLocalBaitScript() {
    const result = await probeUrlBlocked(
      CONFIG.localBaitScript + '?_=' + Date.now(),
      CONFIG.timeouts.scriptFetchMs
    );
    return result === true; // শুধু হার্ড ব্লক গুনছি, timeout না (নিজের সার্ভার তাই timeout মানেই server issue হতে পারে)
  }

  async function checkRemoteAdScripts() {
    const results = await Promise.all(
      CONFIG.baitScriptUrls.map((url) =>
        probeUrlBlocked(url, CONFIG.timeouts.scriptFetchMs)
      )
    );
    // কমপক্ষে একটা হার্ড-ব্লক হলেই যথেষ্ট সিগন্যাল
    return results.some((r) => r === true);
  }

  // -----------------------------------------------------------------------
  // টেকনিক ৪: DNS-resolver self-check (AdGuard DNS / NextDNS ইত্যাদি)
  // -----------------------------------------------------------------------
  // বাগ ফিক্স নোট:
  //   আগে googlesyndication.com/doubleclick.net-এ pixel পাঠিয়ে ব্লক
  //   চেক করা হতো। সমস্যা: এই ডোমেইনগুলো extension filter list-এও থাকে,
  //   তাই "block" পাওয়া মানেই DNS-level কিনা বলা যেত না। ব্রাউজারে
  //   uBlock/ABP থাকলে dns.adguard.com অ্যাপ চালু থাক বা না থাক, ফলাফল
  //   একই (block) আসতো।
  //
  //   এখন প্রতিটা DNS প্রোভাইডারের নিজস্ব "self-check" endpoint কল করা
  //   হয় (dns.adguard.com/test.json)। এই endpoint কোনো filter list-এর
  //   টার্গেট না (এটা ad/tracker ডোমেইন না, প্রোভাইডারের নিজস্ব info
  //   API), তাই extension থাকা-না-থাকার সাথে ফলাফল independent থাকে।
  //   রেসপন্সের ভেতরের ডেটা দিয়েই বোঝা যায় client সেই resolver দিয়ে
  //   resolve হচ্ছে কিনা।
  // ⚠️ CORS নোট: mode:'cors' ব্যবহার করা হয়েছে কারণ রেসপন্স JSON হিসেবে
  // read করতে হবে (no-cors হলে opaque response আসে, .json() কল করা
  // যাবে না)। কিন্তু এর মানে হলো — provider এর endpoint যদি
  // Access-Control-Allow-Origin header না পাঠায়, browser fetch()-কে
  // silently ব্লক করে দেবে (Network ট্যাবে request দেখা যাবে, response
  // ঠিকই এসেছে, কিন্তু JS থেকে পড়া যাবে না — catch ব্লকে চলে যাবে)।
  // এই কারণেই fail/CORS-কে "confirmed blocked" না ধরে null (অনিশ্চিত)
  // রিটার্ন করা হচ্ছে -- ভুল করে false-positive না দেওয়ার জন্য।
  // production এ বসানোর আগে browser console এ সরাসরি টেস্ট করে দেখে
  // নাও endpoint টা আসলেই CORS-friendly response দেয় কিনা; না দিলে
  // নিজের ব্যাকএন্ডে একটা ছোট প্রক্সি বসিয়ে ওখান থেকে কল করা লাগবে।
  async function fetchJson(url, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        method: 'GET',
        mode: 'cors',
        cache: 'no-store',
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (!res.ok) return null;
      return await res.json();
    } catch (err) {
      clearTimeout(timer);
      return null; // fetch fail/timeout/CORS -> "নিশ্চিত করতে পারলাম না", ব্লক প্রমাণ না
    }
  }

  async function checkDnsProviders() {
    const outcomes = await Promise.all(
      CONFIG.dnsSelfCheckProviders.map(async (provider) => {
        const data = await fetchJson(provider.url, CONFIG.timeouts.dnsProbeMs);
        let active = false;
        try {
          active = data ? Boolean(provider.parse(data)) : false;
        } catch (e) {
          active = false; // parse ব্যর্থ হলে "নিশ্চিত না" ধরি, positive না
        }
        return { name: provider.name, active };
      })
    );

    const activeProviders = outcomes.filter((o) => o.active).map((o) => o.name);
    return {
      blocked: activeProviders.length > 0,
      providers: activeProviders,
    };
  }

  // -----------------------------------------------------------------------
  // টেকনিক ৫: MutationObserver — দেরিতে bait সরানো (lazy blockers)
  // -----------------------------------------------------------------------
  // কিছু ব্লকার পেজ লোডের পরপরই কাজ করে না, MutationObserver বা periodic
  // scan দিয়ে কাজ করে (extension এর background cosmetic filtering)।
  // তাই একটা persistent bait রেখে কিছুক্ষণ observe করি, চাইলে caller
  // পরে আবার ফলাফল চেক করতে পারবে।
  function watchBaitRemoval(onDetected, watchMs) {
    const bait = createBaitElement();
    bait.id = 'ad-detector-watch-bait';

    let resolved = false;
    const cleanup = (result) => {
      if (resolved) return;
      resolved = true;
      observer.disconnect();
      if (document.body.contains(bait)) bait.remove();
      onDetected(result);
    };

    const observer = new MutationObserver(() => {
      const stillPresent = document.body.contains(bait);
      if (!stillPresent) {
        cleanup(true);
        return;
      }
      const style = window.getComputedStyle(bait);
      if (style.display === 'none' || bait.offsetHeight === 0) {
        cleanup(true);
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['style', 'class'],
    });

    setTimeout(() => cleanup(false), watchMs);
  }

  // -----------------------------------------------------------------------
  // মূল detect() ফাংশন — সব সিগন্যাল একত্র করে কনফিডেন্স স্কোর বের করে
  // -----------------------------------------------------------------------
  async function detect(options) {
    const opts = Object.assign({}, CONFIG, options || {});

    const detectionPromise = (async () => {
      const [
        baitResult,
        localScriptBlocked,
        remoteScriptBlocked,
        dnsCheck,
      ] = await Promise.all([
        checkBaitElement(),
        checkLocalBaitScript(),
        checkRemoteAdScripts(),
        checkDnsProviders(),
      ]);

      const signals = {
        baitElementHidden: baitResult.hidden,
        baitElementRemoved: baitResult.removed,
        localScriptBlocked,
        remoteScriptBlocked,
        dnsProbeBlocked: dnsCheck.blocked,
      };

      let confidence = 0;
      for (const key of Object.keys(signals)) {
        if (signals[key] && opts.weights[key]) {
          confidence += opts.weights[key];
        }
      }
      confidence = Math.min(1, confidence);

      // কোন লেয়ারে ব্লক হচ্ছে সেটা আলাদাভাবে classify করি —
      // এটা আসল প্রশ্নের একটা গুরুত্বপূর্ণ অংশ: "কোন ধরনের ব্লকার"
      // dnsProbeBlocked এখন নিজে থেকেই নির্ভরযোগ্য (provider self-check
      // থেকে আসা), তাই এটাকে else-if এর সবার শেষে না রেখে independent
      // ভাবে যোগ করছি — DNS-resolver active থাকলে extension না থাকলেও
      // সেটা রিপোর্ট হওয়া উচিত।
      const layers = [];
      if (signals.baitElementHidden || signals.baitElementRemoved) {
        layers.push('browser_or_extension'); // cosmetic filtering -> extension/Brave/Firefox
      }
      if (signals.localScriptBlocked || signals.remoteScriptBlocked) {
        layers.push('extension_network_filter'); // request filtering -> extension/browser network rule
      }
      if (signals.dnsProbeBlocked) {
        layers.push('dns_resolver'); // dns.adguard.com ইত্যাদি self-check অনুযায়ী active DNS filtering
      }
      const layer = layers.length ? layers.join('+') : 'none';

      return {
        blocked: confidence >= opts.confidenceThreshold,
        confidence: Number(confidence.toFixed(2)),
        layer,
        layers,
        dnsProviders: dnsCheck.providers, // কোন কোন DNS প্রোভাইডার active ধরা পড়েছে
        signals,
      };
    })();

    // পুরো প্রসেসের একটা হার্ড ক্যাপ — কোনো probe hang করলেও UX ব্লক না হোক
    return withTimeout(detectionPromise, opts.timeouts.overallMs, {
      blocked: false,
      confidence: 0,
      layer: 'unknown',
      signals: {},
      timedOut: true,
    });
  }

  // -----------------------------------------------------------------------
  // পাবলিক API
  // -----------------------------------------------------------------------
  const AdblockDetector = {
    detect,
    watchBaitRemoval,
    CONFIG,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = AdblockDetector;
  } else {
    global.AdblockDetector = AdblockDetector;
  }
})(typeof window !== 'undefined' ? window : globalThis);
