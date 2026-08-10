sudo apt-get update
sudo apt-get install git
git clone https://github.com/alexpotv/9CarPlay.git

sudo apt install -y bluez bluez-tools python3-dbus python3-gi ffmpeg

sudo systemctl enable --now bluetooth
sudo rfkill unblock bluetooth 


sudo nano /etc/bluetooth/main.conf                                                  
  Under the [General] section, add (or edit if a Class = line already exists):        
  Class = 0x5A020C                                                                    
  That value is major=Phone, minor=Smartphone, with                                   
  Audio/Networking/Object-Transfer/Capturing service bits set — closer to what a real 
  phone advertises than a bare major/minor pair (confirmed necessary on real hardware;
  without it the car never shows a phone icon).  
 
sudo nano /boot/firmware/config.txt

  Sous rpi5 (ou éeuivalent):
  dtoverlay=dwc2,dr_mode=peripheral

sudo systemctl restart bluetooth
sudo rfkill unblock bluetooth

cd 9CarPlay/pi/bluetooth-test                                                                
sudo python3 hfp_ag.py

-- PAIR --
Dans bluetoothctl:
- pairable on
- discoverable on
- Sur le head unit, rechercher, sélectionner, 'yes' à tout

Une fois stable:
cd ../iap1                                                                          
sudo python3 btsdp_iap.py

Puis lancer HondaLink