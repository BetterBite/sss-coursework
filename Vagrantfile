     
# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.define "box" do |box|
                box.vm.box = "ubuntu/bionic64"
                box.vm.hostname = "coursework"
                box.vm.provider "virtualbox" do |virtualbox|
        virtualbox.name="coursework"
    end
 end
   config.vm.provision "shell", inline: <<-SHELL
    sudo dpkg --configure -a
    sudo sysctl -w kernel.randomize_va_space=0
    echo "Updating system and installing Python3, pip, and ROPgadget..."
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip
    sudo apt-get install -y wget unzip
    sudo apt-get install -y gdb
    pip3 install ropgadget
    echo "ROPgadget installed successfully."
    sudo apt-get install -y git
    wget https://github.com/BetterBite/sss-coursework/archive/refs/heads/integrate.zip -O /home/vagrant/repository.zip
    unzip /home/vagrant/repository.zip -d /home/vagrant
    mv ./sss-coursework-main/* ./
    rm -r sss-coursework-main
  SHELL
end
