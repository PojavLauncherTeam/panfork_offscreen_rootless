`Mesa <https://mesa3d.org>`_ - The 3D Graphics Library
======================================================

Valhall v10 "CSF" support branch—for Mali G710/G610.

Note that firmware is required for these GPUs, for RK3588 try
downloading the file from the Rockchip `libmali
<https://github.com/JeffyCN/rockchip_mirrors/tree/libmali/firmware/g610>`_
repo, and placing it in ``/lib/firmware/``.

Source
------

This repository lives at https://gitlab.com/panfork/mesa, and is a
fork, so not supported by upstream.

Upstream source is at https://gitlab.freedesktop.org/mesa/mesa.

Build & install
---------------

.. code-block:: sh

  $ mkdir build
  $ cd build
  $ meson .. -Dgallium-drivers=panfrost -Dvulkan-drivers= -Dllvm=disabled --prefix=/opt/panfrost
  $ sudo ninja install

Usage
-----

So far testing has been done from a Weston session launched with the
blob, but other setups might work:

.. code-block:: sh

  $ LD_LIBRARY_PATH=/opt/panfrost/lib/aarch64-linux-gnu glmark2-es2-wayland

The exact path to the library directory (which should contain
``libGL.so`` etc.) may differ between distros.

To avoid the blob completely, Sway seems to work with Panfrost, though
Xwayland seems to be broken at the moment:

.. code-block:: sh

  $ LD_LIBRARY_PATH=/opt/panfrost/lib/aarch64-linux-gnu sway
