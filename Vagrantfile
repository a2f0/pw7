Vagrant.configure("2") do |config|
    config.vm.box = "debian/buster64"
    config.vm.provider 'virtualbox' do |v|
        v.gui = true
        v.customize ["modifyvm", :id, "--graphicscontroller", "vmsvga"]
        v.customize ["modifyvm", :id, "--vram", "64"]
        v.customize ["modifyvm", :id, "--vrde", "off"]
    end
    config.vm.provision "ansible" do |ansible|
        ansible.playbook = "playbook.yaml"
    end
  end
  