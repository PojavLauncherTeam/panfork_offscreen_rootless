`Mesa <https://mesa3d.org>`_ - The 3D Graphics Library
======================================================

Valhall v10 "CSF" support branch—for Mali G710/G610.

Note that firmware is required for these GPUs, for RK3588 try
downloading the file from the Rockchip `libmali
<https://github.com/JeffyCN/rockchip_mirrors/tree/libmali/firmware/g610>`_
repo, and placing it in ``/lib/firmware/``.

Windowing system support
------------------------

Panfrost Wayland compositor (wlroots):

#. Panfrost Wayland clients
#. Panfrost X11 clients via Xwayland [1]_

Panfrost Wayland compositor (non-wlroots):

#. Panfrost Wayland clients
#. Panfrost X11 clients via Xwayland
#. Blob Wayland clients

Blob Wayland compositor:

#. Panfrost Wayland clients
#. Blob Wayland clients

Panfrost Xorg server: [2]_

#. Panfrost X11 clients

Applications using KMS/DRM will also work.

.. [1] Requires ``CONFIG_DRM_IGNORE_IOTCL_PERMIT`` to be disabled in
       the kernel configuration. The option is broken and should never
       be enabled anyway.

.. [2] For Radxa Debian/Ubuntu, the ``xserver-xorg-core`` version
       installed by default is not compatible with Panfrost. To switch
       between the upstream and Rockchip versions, run:

.. code-block:: sh

  $ sudo apt install xserver-xorg-core="$(apt-cache show xserver-xorg-core | grep Version | grep -v "$(dpkg -s xserver-xorg-core | grep Version)" | cut -d" " -f2)"

Broken combinations:

#. Panfrost wlroots + Blob Wayland does not work because wlroots does
   not expose the ``mali_buffer_sharing`` protocol. This might be
   fixable.
#. Blob Xorg server + Panfrost X11 raises ``CS_INHERIT_FAULT``s
#. Panfrost Xorg server + Blob X11 raises ``GPU_SHAREABILITY_FAULT``s
#. Blob Wayland compositor + Panfrost X11 does not work because the
   blob does not expose the required protocols for Xwayland
   acceleration to work
#. Any Wayland compositor + Blob X11 does not work because Xwayland
   exposes DRI3, but Blob X11 drivers only work with DRI2

Source
------

This repository lives at https://gitlab.com/panfork/mesa, and is a
fork, so not supported by upstream.

Upstream source is at https://gitlab.freedesktop.org/mesa/mesa.

Depdendencies
-------------

For Debian-based distributions:

.. code-block:: sh

  $ sudo apt install build-essential meson git python3-mako libexpat1-dev bison flex libwayland-egl-backend-dev libxext-dev libxfixes-dev libxcb-glx0-dev libxcb-shm0-dev libxcb-dri2-0-dev libxcb-dri3-dev libxcb-present-dev libxshmfence-dev libxxf86vm-dev libxrandr-dev

Also needed is ``libdrm`` and ``wayland-protocols``, but those
packages are too old in Debian Bullseye, and must be compiled from
source:

.. code-block:: sh

  $ git clone https://gitlab.freedesktop.org/mesa/drm
  $ mkdir drm/build
  $ cd drm/build
  $ meson
  $ sudo ninja install

.. code-block:: sh

  $ git clone https://gitlab.freedesktop.org/wayland/wayland-protocols
  $ mkdir wayland-protocols/build
  $ cd wayland-protocols/build
  $ git checkout 1.24
  $ meson
  $ sudo ninja install

Build & install
---------------

To install to ``/opt/panfrost``:

.. code-block:: sh

  $ mkdir build
  $ cd build
  $ meson -Dgallium-drivers=panfrost -Dvulkan-drivers= -Dllvm=disabled --prefix=/opt/panfrost
  $ sudo ninja install

Usage
-----

To run an application with Panfrost (note the windowing system support
section above):

.. code-block:: sh

  $ LD_LIBRARY_PATH=/opt/panfrost/lib/aarch64-linux-gnu glmark2-es2-wayland

To use Panfrost by default, add the directory where you installed it
to the library search path:

.. code-block:: sh

  $ echo /opt/panfrost/lib/aarch64-linux-gnu | sudo tee /etc/ld.so.conf.d/0-panfrost.conf
  $ sudo ldconfig
