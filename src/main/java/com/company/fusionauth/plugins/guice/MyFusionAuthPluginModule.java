package com.company.fusionauth.plugins.guice;

import com.company.fusionauth.plugins.MyExamplePasswordEncryptor;
import com.google.inject.AbstractModule;
import com.google.inject.multibindings.MapBinder;
import io.fusionauth.plugin.spi.PluginModule;
import io.fusionauth.plugin.spi.security.PasswordEncryptor;

/**
 * @author Daniel DeGroff
 */
@PluginModule
public class MyFusionAuthPluginModule extends AbstractModule {
  @Override
  protected void configure() {
    MapBinder<String, PasswordEncryptor> passwordEncryptorMapBinder = MapBinder.newMapBinder(binder(), String.class, PasswordEncryptor.class);

    // TODO :
    //   1. Add one or more bindings here
    //   2. Name your binding. This will be the value you set in the 'encryptionScheme' on the user to utilize this encryptor.
    passwordEncryptorMapBinder.addBinding("example-hash").to(MyExamplePasswordEncryptor.class);
  }
}
