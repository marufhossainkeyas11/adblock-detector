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
 *   4. DNS-sinkhole probe    -> Pi-hole/NextDNS/router-level DNS block ধরে
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

    // DNS-sinkhole probe: এই ডোমেইনগুলো prod-এ known-ad/tracker হিসেবে
    // চিহ্নিত এবং প্রায় সব DNS blocklist (Pi-hole/NextDNS ডিফল্ট লিস্ট,
    // Steven Black hosts, OISD) এ থাকে। image pixel দিয়ে লোড ট্রাই করা
    // হয় কারণ img element cross-origin এরর ছাড়াই load/error event দেয়।
    dnsProbeTargets: [
      'https://pagead2.googlesyndication.com/pagead/images/pixel.gif',
      'https://googleads.g.doubleclick.net/pagead/id',
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
  // টেকনিক ৪: DNS-level sinkhole probe (Pi-hole / NextDNS / router)
  // -----------------------------------------------------------------------
  // DNS sinkhole হলে ব্রাউজার সেই ডোমেইনের IP-ই resolve করতে পারে না,
  // ফলে request timeout/network-error এ পড়ে (extension ব্লকের চেয়ে ধীর,
  // কারণ TCP handshake ট্রাই হওয়ার সুযোগও পায় না বা bogus IP তে গিয়ে
  // hang করে)। তাই timeout কেও এখানে positive সিগন্যাল ধরছি, কারণ এই
  // ডোমেইনগুলো সচরাচর আপ থাকে ও দ্রুত রেসপন্স দেয়।
  function dnsProbeViaImage(url, timeoutMs) {
    return new Promise((resolve) => {
      const img = new Image();
      let settled = false;

      const finish = (blocked) => {
        if (settled) return;
        settled = true;
        resolve(blocked);
      };

      const timer = setTimeout(() => finish(true), timeoutMs);

      img.onload = () => {
        clearTimeout(timer);
        finish(false);
      };
      img.onerror = () => {
        clearTimeout(timer);
        // onerror হতে পারে blocked pixel (1x1 gif সহ), বা সত্যিকারের ব্লক
        finish(true);
      };

      img.src = url + (url.includes('?') ? '&' : '?') + '_=' + Date.now();
    });
  }

  async function checkDnsSinkhole() {
    const results = await Promise.all(
      CONFIG.dnsProbeTargets.map((url) =>
        dnsProbeViaImage(url, CONFIG.timeouts.dnsProbeMs)
      )
    );
    // দুইটার মধ্যে অন্তত একটা ব্লক হলে DNS/network-level ফিল্টারিং সন্দেহ করি
    const blockedCount = results.filter(Boolean).length;
    return blockedCount >= 1;
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
        dnsBlocked,
      ] = await Promise.all([
        checkBaitElement(),
        checkLocalBaitScript(),
        checkRemoteAdScripts(),
        checkDnsSinkhole(),
      ]);

      const signals = {
        baitElementHidden: baitResult.hidden,
        baitElementRemoved: baitResult.removed,
        localScriptBlocked,
        remoteScriptBlocked,
        dnsProbeBlocked: dnsBlocked,
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
      let layer = 'none';
      if (signals.baitElementHidden || signals.baitElementRemoved) {
        layer = 'browser_or_extension'; // cosmetic filtering -> extension/Brave/Firefox
      } else if (signals.localScriptBlocked || signals.remoteScriptBlocked) {
        layer = 'extension_network_filter'; // request filtering -> extension/browser network rule
      } else if (signals.dnsProbeBlocked) {
        layer = 'dns_or_network'; // DOM/script signal নাই কিন্তু network request যাচ্ছে না -> DNS/VPN/router
      }

      return {
        blocked: confidence >= opts.confidenceThreshold,
        confidence: Number(confidence.toFixed(2)),
        layer,
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
