export const UPDATER_LAYOUTS = Object.freeze({
  "linux-x86_64": Object.freeze([
    Object.freeze({
      bundleType: "appimage",
      directory: "appimage",
      signatureSuffix: ".AppImage.sig",
      targetKeys: Object.freeze(["linux-x86_64", "linux-x86_64-appimage"]),
    }),
    Object.freeze({
      bundleType: "deb",
      directory: "deb",
      signatureSuffix: ".deb.sig",
      targetKeys: Object.freeze(["linux-x86_64-deb"]),
    }),
    Object.freeze({
      bundleType: "rpm",
      directory: "rpm",
      signatureSuffix: ".rpm.sig",
      targetKeys: Object.freeze(["linux-x86_64-rpm"]),
    }),
  ]),
  "macos-universal": Object.freeze([
    Object.freeze({
      bundleType: "app",
      directory: "macos",
      signatureSuffix: ".app.tar.gz.sig",
      targetKeys: Object.freeze([
        "darwin-x86_64",
        "darwin-x86_64-app",
        "darwin-aarch64",
        "darwin-aarch64-app",
      ]),
    }),
  ]),
  "windows-x86_64": Object.freeze([
    Object.freeze({
      bundleType: "nsis",
      directory: "nsis",
      signatureSuffix: ".exe.sig",
      targetKeys: Object.freeze(["windows-x86_64", "windows-x86_64-nsis"]),
    }),
    Object.freeze({
      bundleType: "msi",
      directory: "msi",
      signatureSuffix: ".msi.sig",
      targetKeys: Object.freeze(["windows-x86_64-msi"]),
    }),
  ]),
});

export const updaterLayoutsFor = (platform) => {
  const layouts = UPDATER_LAYOUTS[platform];
  if (!layouts) {
    throw new Error(`unsupported release platform: ${platform}`);
  }
  return layouts;
};

export const ALL_UPDATER_TARGET_KEYS = Object.freeze(
  Object.values(UPDATER_LAYOUTS).flatMap((layouts) =>
    layouts.flatMap((layout) => [...layout.targetKeys]),
  ),
);
