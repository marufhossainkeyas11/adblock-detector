/**
 * useAdblockDetector.js
 * ------------------------------------------------------------------
 * adblock-detector.js এর React hook wrapper।
 * ব্যবহার:
 *
 *   import { useAdblockDetector } from './useAdblockDetector';
 *
 *   function App() {
 *     const { status, result, recheck } = useAdblockDetector({ autoRun: true });
 *
 *     if (status === 'checking') return <Loader />;
 *     if (status === 'blocked') return <AdblockNotice onRecheck={recheck} />;
 *     return <MainApp />;
 *   }
 *
 * নোট: এই ফাইলটা ব্যবহারের আগে adblock-detector.js কে ঠিক
 * তোমার bundler-এর মতো import করে নিতে হবে অথবা window.AdblockDetector
 * হিসেবে গ্লোবালি লোড করে নিতে হবে (script tag দিয়ে, যেমন demo.html তে
 * দেখানো হয়েছে) — কারণ এক্সটেনশন ব্লকাররা webpack bundle এর ভেতরের
 * script নামের চেয়ে আলাদা ফাইলনেম-ভিত্তিক প্রোবেই বেশি সহজে ধরে।
 * ------------------------------------------------------------------
 */
import { useCallback, useEffect, useRef, useState } from 'react';

// window.AdblockDetector গ্লোবাল হিসেবে ধরে নিচ্ছি (script tag দিয়ে লোড করা)
// bundler দিয়ে import করতে চাইলে: import AdblockDetector from './adblock-detector';
function getEngine() {
  if (typeof window !== 'undefined' && window.AdblockDetector) {
    return window.AdblockDetector;
  }
  throw new Error(
    'AdblockDetector গ্লোবালি পাওয়া যায়নি। adblock-detector.js কে <script> ট্যাগ দিয়ে আগে লোড করুন।'
  );
}

export function useAdblockDetector(options = {}) {
  const { autoRun = true, minConfidence = 0.5 } = options;

  // status: 'idle' | 'checking' | 'blocked' | 'clean' | 'error'
  const [status, setStatus] = useState('idle');
  const [result, setResult] = useState(null);
  const mountedRef = useRef(true);

  const runCheck = useCallback(async () => {
    setStatus('checking');
    try {
      const engine = getEngine();
      const res = await engine.detect();

      if (!mountedRef.current) return;

      setResult(res);
      setStatus(res.confidence >= minConfidence ? 'blocked' : 'clean');
    } catch (err) {
      if (!mountedRef.current) return;
      console.error('Adblock detection ব্যর্থ হয়েছে:', err);
      setStatus('error');
    }
  }, [minConfidence]);

  useEffect(() => {
    mountedRef.current = true;
    if (autoRun) {
      runCheck();
    }
    return () => {
      mountedRef.current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoRun]);

  return { status, result, recheck: runCheck };
}
