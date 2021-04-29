Vagrant.configure("2") do |config|
    config.vbguest.auto_update = false
    config.vm.box = "debian/buster64"
    config.vm.provider 'virtualbox' do |v|
        v.memory = 2048
        v.cpus = 1
        v.gui = true
        v.customize ["modifyvm", :id, "--graphicscontroller", "vmsvga"]
        v.customize ["modifyvm", :id, "--vram", "8"]
        v.customize ["modifyvm", :id, "--vrde", "off"]
    end
    config.vm.provision "ansible" do |ansible|
        ansible.playbook = "playbook.yaml"
    end
  end
  