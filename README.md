## Example Password Encryptor 

If you need to write a custom encryptor to import users into FusionAuth, you may use this example build. This is intended to be used with the Writing a Plugin guide provided in the FusionAuth documentation. 

Writing a Plugin guide is found here:  https://fusionauth.io/docs/v1/tech/plugins/writing-a-plugin


### Building

### Building with Maven


```bash
$ mvn install
```


### Building with Savant

**Note:** This project uses the Savant build tool. To compile using Savant, follow these instructions:

```bash
$ mkdir ~/savant
$ cd ~/savant
$ wget http://savant.inversoft.org/org/savantbuild/savant-core/1.0.0/savant-1.0.0.tar.gz
$ tar xvfz savant-1.0.0.tar.gz
$ ln -s ./savant-1.0.0 current
$ export PATH=$PATH:~/savant/current/bin/
```