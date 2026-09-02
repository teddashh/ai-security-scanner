export const MOBILE_NAVIGATION_MEDIA_QUERY = "(max-width: 820px)";

/**
 * The drawer is modal only while its mobile breakpoint is active. Applying
 * this same reconciliation to viewport changes closes an open mobile drawer
 * before desktop navigation hides its menu and close controls.
 */
export const reconcileMobileNavigationOpen = (
  requestedOpen: boolean,
  narrowViewport: boolean,
): boolean => requestedOpen && narrowViewport;
