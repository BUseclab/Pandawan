# Set the FirmSolo, Firmadyne, FirmAE and output directories here
import os

INSTALL_DIR = os.getenv("INSTALL_DIR") or "/"

pandawan_dir = os.path.join(INSTALL_DIR, "Pandawan/")
firmsolo_dir = os.path.join(INSTALL_DIR, "FirmSolo/")
firmae_dir = os.path.join(INSTALL_DIR, "FirmAE/")
firmadyne_dir = os.path.join(INSTALL_DIR, "firmadyne/")
output_dir = os.path.join(INSTALL_DIR, "output/")
