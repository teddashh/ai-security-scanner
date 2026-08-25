# syntax=docker/dockerfile:1.7
#
# Release-only builder for the Linux managed-runtime QEMU helper. The output is
# copied into a Tauri resource bundle; this image is never shipped to users.
FROM alpine@sha256:1beb0dc0a51de7ff38e3b5274078a2e0b81113ba5c7535e1a03d5913a5edbda3 AS build

ARG TARGETPLATFORM
RUN test "$TARGETPLATFORM" = "linux/amd64" \
    && apk add --no-cache \
      build-base=0.5-r3 \
      glib-dev=2.86.3-r0 \
      glib-static=2.86.3-r0 \
      libffi-dev=3.5.2-r0 \
      linux-headers=6.16.12-r0 \
      meson=1.9.1-r0 \
      pcre2-dev=10.47-r0 \
      pcre2-static=10.47-r0 \
      pixman-dev=0.46.4-r0 \
      pixman-static=0.46.4-r0 \
      pkgconf=2.5.1-r0 \
      py3-pip=25.1.1-r1 \
      py3-setuptools=80.9.0-r2 \
      py3-wheel=0.46.3-r0 \
      python3=3.12.14-r0 \
      zlib-dev=1.3.2-r0 \
      zlib-static=1.3.2-r0

COPY . /src/
COPY --from=launcher /qemu-launcher.c /src/ass-qemu-launcher.c
WORKDIR /src
RUN ./configure \
      --prefix=/opt/managed-qemu \
      --target-list=x86_64-softmmu \
      --static \
      --disable-download \
      --without-default-features \
      --enable-kvm \
      --enable-fdt=internal \
      --enable-pixman \
      --enable-tools \
      --enable-strip \
      --disable-docs \
      --disable-guest-agent \
      --disable-modules \
      --disable-slirp \
      --audio-drv-list= \
      --with-pkgversion=ai-security-scanner-managed \
    && samu -C build qemu-system-x86_64 qemu-img \
    && DESTDIR=/stage samu -C build install \
    && mv /stage/opt/managed-qemu/bin/qemu-system-x86_64 \
          /stage/opt/managed-qemu/bin/qemu-system-x86_64.real \
    && cc -static -Os -s -Wall -Wextra -Werror \
          -o /stage/opt/managed-qemu/bin/qemu-system-x86_64 \
          /src/ass-qemu-launcher.c

FROM scratch AS export
COPY --from=build /stage/opt/managed-qemu/bin/qemu-system-x86_64 /bin/qemu-system-x86_64
COPY --from=build /stage/opt/managed-qemu/bin/qemu-system-x86_64.real /bin/qemu-system-x86_64.real
COPY --from=build /stage/opt/managed-qemu/bin/qemu-img /bin/qemu-img
COPY --from=build /stage/opt/managed-qemu/share/qemu /share/qemu
