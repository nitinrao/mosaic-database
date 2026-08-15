"use client";

// The widget itself is a plain script appended to <body>, which React does not own. The footer
// entry is rendered here instead of injected, so nothing is inserted into hydrated markup.
export function FeedbackLink() {
  return (
    <button
      type="button"
      className="feedback-footer-link"
      onClick={() => window.mosaicFeedback?.open()}
    >
      Feedback
    </button>
  );
}

declare global {
  interface Window {
    mosaicFeedback?: { open: () => void; close: () => void };
  }
}
