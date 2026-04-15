<todos title="Dashboard open-source cleanup and input UX" rule="Review steps frequently throughout the conversation and DO NOT stop between steps unless they explicitly require it.">
- [x] inspect-reflex-banner-and-input-flow: Inspect Reflex config and dashboard layout/input handlers to find the source of the Built with Reflex banner, current prompt placement, and Enter-key behavior. 🔴
  _Confirmed Reflex open-source config exposes `show_built_with_reflex`, the checked-in source had no prompt bar, and the live screenshot was coming from a stale generated bundle._
- [x] remove-reflex-banner-and-reposition-input: Update Reflex configuration and dashboard layout so the Reflex badge is removed if supported and the prompt input stays docked at the bottom of the screen. 🔴
  _Disabled the sticky badge in `rxconfig.py` and rebuilt the page as a flex column with a bottom command dock under the response-only output region._
- [x] enable-enter-to-submit-and-verify: Wire Enter key submission for the prompt field and run focused validation for dashboard behavior after the UI changes. 🔴
  _Used a form-backed `rx.text_area` with `enter_key_submit=True`, then passed focused pytest coverage and a production `reflex export --no-zip` compile check._
</todos>

<!-- Auto-generated todo section -->
<!-- Add your custom Copilot instructions below -->
