/*
 * Copyright 2017 The Mifos Initiative.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.mifos;

import ch.vorburger.mariadb4j.DB;
import io.mifos.anubis.api.v1.domain.AllowedOperation;
import io.mifos.anubis.api.v1.domain.Signature;
import io.mifos.core.api.config.EnableApiFactory;
import io.mifos.core.api.context.AutoSeshat;
import io.mifos.core.api.context.AutoUserContext;
import io.mifos.core.api.util.ApiConstants;
import io.mifos.core.api.util.ApiFactory;
import io.mifos.core.lang.AutoTenantContext;
import io.mifos.core.lang.security.RsaPublicKeyBuilder;
import io.mifos.core.test.env.TestEnvironment;
import io.mifos.core.test.servicestarter.EurekaForTest;
import io.mifos.core.test.servicestarter.IntegrationTestEnvironment;
import io.mifos.core.test.servicestarter.Microservice;
import io.mifos.office.api.v1.client.OfficeClient;
import io.mifos.office.api.v1.domain.ContactDetail;
import io.mifos.office.api.v1.domain.Employee;
import io.mifos.office.api.v1.domain.Office;
import io.mifos.identity.api.v1.client.IdentityService;
import io.mifos.identity.api.v1.domain.*;
import io.mifos.provisioner.api.v1.client.ProvisionerService;
import io.mifos.provisioner.api.v1.domain.*;
import org.cassandraunit.utils.EmbeddedCassandraServerHelper;
import org.junit.*;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.Base64Utils;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@SuppressWarnings("SpringAutowiredFieldsWarningInspection")
@RunWith(SpringRunner.class)
@SpringBootTest()
public class WorkflowTenantProvisioning {
  private static final String TEST_TENANT = "provisioning_integration_test";
  private static final String CLIENT_ID = "luckyLeprachaun";
  private static Microservice<ProvisionerService> provisionerService;
  private static Microservice<IdentityService> identityService;
  private static Microservice<OfficeClient> officeClient;
  private static DB EMBEDDED_MARIA_DB;


  public PublicKey getPublicKey() {
    final Signature sig = identityService.api().getSignature();

    return new RsaPublicKeyBuilder()
            .setPublicKeyMod(sig.getPublicKeyMod())
            .setPublicKeyExp(sig.getPublicKeyExp())
            .build();
  }

  @Configuration
  @EnableApiFactory
  public static class TestConfiguration {
    public TestConfiguration() {
      super();
    }

    @Bean()
    public Logger logger() {
      return LoggerFactory.getLogger("test-logger");
    }
  }

  @ClassRule
  public static final EurekaForTest eurekaForTest = new EurekaForTest();

  @ClassRule
  public static final IntegrationTestEnvironment integrationTestEnvironment = new IntegrationTestEnvironment();

  @Autowired
  private ApiFactory apiFactory;


  public WorkflowTenantProvisioning() {
    super();
  }

  @BeforeClass
  public static void setup() throws Exception {

    // start embedded Cassandra
    EmbeddedCassandraServerHelper.startEmbeddedCassandra(TimeUnit.SECONDS.toMillis(30L));
    // start embedded MariaDB
    EMBEDDED_MARIA_DB = DB.newEmbeddedDB(3306);
    EMBEDDED_MARIA_DB.start();

    provisionerService = new Microservice<>(ProvisionerService.class, "provisioner", "0.1.0-BUILD-SNAPSHOT", integrationTestEnvironment);
    final TestEnvironment provisionerTestEnvironment = provisionerService.getProcessEnvironment();
    provisionerTestEnvironment.addSystemPrivateKeyToProperties();
    provisionerTestEnvironment.setProperty("system.initialclientid", CLIENT_ID);
    provisionerService.start();

    identityService = new Microservice<>(IdentityService.class, "identity", "0.1.0-BUILD-SNAPSHOT", integrationTestEnvironment);
    identityService.start();
    officeClient = new Microservice<>(OfficeClient.class, "office", "0.1.0-BUILD-SNAPSHOT", integrationTestEnvironment);
    officeClient.start();
  }

  @AfterClass
  public static void tearDown() throws Exception {
    officeClient.kill();
    identityService.kill();
    provisionerService.kill();

    //EmbeddedCassandraServerHelper.cleanEmbeddedCassandra();
    EMBEDDED_MARIA_DB.stop();
  }

  @Before
  public void before()
  {
    provisionerService.setApiFactory(apiFactory);
    identityService.setApiFactory(apiFactory);
    officeClient.setApiFactory(apiFactory);
  }

  @Test
  public void test() throws InterruptedException {
    final String tenantAdminPassword = provisionAppsViaSeshat();

    try (final AutoTenantContext ignore = new AutoTenantContext(TEST_TENANT)) {
      final Authentication adminPasswordOnlyAuthentication = identityService.api().login("antony", tenantAdminPassword);
      try (final AutoUserContext ignored = new AutoUserContext("antony", adminPasswordOnlyAuthentication.getAccessToken()))
      {
        identityService.api().changeUserPassword("antony", new Password(tenantAdminPassword));
        Thread.sleep(1000L); //TODO: replace this with an event listener.
      }

      final Authentication adminAuthentication = identityService.api().login("antony", tenantAdminPassword);

      final UserWithPassword officeAdministratorUser;
      final UserWithPassword employeeUser;
      final Role employeeRole;
      try (final AutoUserContext ignored = new AutoUserContext("antony", adminAuthentication.getAccessToken())) {
        checkCreationOfPermittableGroupsInIsis();
        employeeRole = makeEmployeeRole();
        final Role officeAdministratorRole = makeOfficeAdministratorRole();

        identityService.api().createRole(employeeRole);
        identityService.api().createRole(officeAdministratorRole);

        officeAdministratorUser = new UserWithPassword();
        officeAdministratorUser.setIdentifier("narmer");
        officeAdministratorUser.setPassword(encodePassword("3100BC"));
        officeAdministratorUser.setRole(officeAdministratorRole.getIdentifier());

        identityService.api().createUser(officeAdministratorUser);
        Thread.sleep(500L); //TODO: replace this with an event listener.

        identityService.api().logout();
      }

      final Authentication officeAdministratorPasswordOnlyAuthentication = identityService.api().login(officeAdministratorUser.getIdentifier(), officeAdministratorUser.getPassword());
      try (final AutoUserContext ignored = new AutoUserContext(officeAdministratorUser.getIdentifier(), officeAdministratorPasswordOnlyAuthentication.getAccessToken()))
      {
        identityService.api().changeUserPassword(officeAdministratorUser.getIdentifier(), new Password(officeAdministratorUser.getPassword()));
        Thread.sleep(1500L); //TODO: replace this with an event listener.
      }

      final Authentication officeAdministratorAuthentication = identityService.api().login(officeAdministratorUser.getIdentifier(), officeAdministratorUser.getPassword());

      try (final AutoUserContext ignored = new AutoUserContext(officeAdministratorUser.getIdentifier(), officeAdministratorAuthentication.getAccessToken())) {
        final Set<Permission> userPermissions = identityService.api().getUserPermissions(officeAdministratorUser.getIdentifier());
        Assert.assertTrue(userPermissions.contains(new Permission(io.mifos.office.api.v1.PermittableGroupIds.EMPLOYEE_MANAGEMENT, AllowedOperation.ALL)));
        Assert.assertTrue(userPermissions.contains(new Permission(io.mifos.office.api.v1.PermittableGroupIds.OFFICE_MANAGEMENT, AllowedOperation.ALL)));

        final Office office = new Office();
        office.setIdentifier("abydos");
        office.setName("Abydos");
        office.setDescription("First bank of the nile");
        WorkflowTenantProvisioning.officeClient.api().createOffice(office);

        Thread.sleep(500L); //TODO: replace this with an event listener.

        employeeUser = new UserWithPassword();
        employeeUser.setIdentifier("iryhor");
        employeeUser.setPassword(encodePassword("3150BC"));
        employeeUser.setRole(employeeRole.getIdentifier());

        identityService.api().createUser(employeeUser);

        final Employee employee = new Employee();
        employee.setIdentifier(employeeUser.getIdentifier());
        employee.setGivenName("Iry");
        employee.setSurname("Hor");
        employee.setAssignedOffice("abydos");
        WorkflowTenantProvisioning.officeClient.api().createEmployee(employee);

        Thread.sleep(500L); //TODO: replace this with an event listener.

        identityService.api().logout();
      }

      final Authentication employeePasswordOnlyAuthentication = identityService.api().login(employeeUser.getIdentifier(), employeeUser.getPassword());
      try (final AutoUserContext ignored = new AutoUserContext(employeeUser.getIdentifier(), employeePasswordOnlyAuthentication.getAccessToken()))
      {
        identityService.api().changeUserPassword(employeeUser.getIdentifier(), new Password(employeeUser.getPassword()));
        Thread.sleep(1000L); //TODO: replace this with an event listener.
      }

      final Authentication employeeAuthentication = identityService.api().login(employeeUser.getIdentifier(), employeeUser.getPassword());

      try (final AutoUserContext ignored = new AutoUserContext(employeeUser.getIdentifier(), employeeAuthentication.getAccessToken())) {
        final ContactDetail contactDetail = new ContactDetail();
        contactDetail.setType(ContactDetail.Type.EMAIL.toString());
        contactDetail.setValue("iryhor@ancient.eg");
        contactDetail.setGroup(ContactDetail.Group.PRIVATE.toString());
        officeClient.api().setContactDetails(employeeUser.getIdentifier(), Collections.singletonList(contactDetail));

        Thread.sleep(500L); //TODO: replace this with an event listener.

        final Employee employee = officeClient.api().findEmployee(employeeUser.getIdentifier());
        Assert.assertNotNull(employeeUser);

        Assert.assertEquals(employee.getIdentifier(), employeeUser.getIdentifier());
        Assert.assertEquals(employee.getAssignedOffice(), "abydos");
        Assert.assertEquals(employee.getGivenName(), "Iry");
        Assert.assertEquals(employee.getSurname(), "Hor");
        Assert.assertEquals(employee.getContactDetails(), Collections.singletonList(contactDetail));

        identityService.api().logout();
      }
    }
  }

  private void checkCreationOfPermittableGroupsInIsis() {
    identityService.api().getPermittableGroup(io.mifos.identity.api.v1.PermittableGroupIds.ROLE_MANAGEMENT);
    identityService.api().getPermittableGroup(io.mifos.identity.api.v1.PermittableGroupIds.IDENTITY_MANAGEMENT);
    identityService.api().getPermittableGroup(io.mifos.identity.api.v1.PermittableGroupIds.SELF_MANAGEMENT);
    identityService.api().getPermittableGroup(io.mifos.office.api.v1.PermittableGroupIds.EMPLOYEE_MANAGEMENT);
    identityService.api().getPermittableGroup(io.mifos.office.api.v1.PermittableGroupIds.OFFICE_MANAGEMENT);
    identityService.api().getPermittableGroup(io.mifos.office.api.v1.PermittableGroupIds.SELF_MANAGEMENT);
  }

  private String provisionAppsViaSeshat() throws InterruptedException {
    final AuthenticationResponse authenticationResponse
            = provisionerService.api().authenticate(CLIENT_ID, ApiConstants.SYSTEM_SU, "oS/0IiAME/2unkN1momDrhAdNKOhGykYFH/mJN20");

    try (final AutoSeshat ignored = new AutoSeshat(authenticationResponse.getToken())) {
      final Tenant tenant = makeTenant();

      provisionerService.api().createTenant(tenant);

      final Application isisApp = new Application();
      isisApp.setName(identityService.name());
      isisApp.setHomepage(identityService.uri());
      isisApp.setDescription("identity manager");
      isisApp.setVendor("fineract");

      provisionerService.api().createApplication(isisApp);

      final AssignedApplication isisAssigned = new AssignedApplication();
      isisAssigned.setName(identityService.name());

      final IdentityManagerInitialization isisAdminPassword
              = provisionerService.api().assignIdentityManager(tenant.getIdentifier(), isisAssigned);

      final Application horusApp = new Application();
      horusApp.setName(officeClient.name());
      horusApp.setHomepage(officeClient.uri());
      horusApp.setDescription("organization manager");
      horusApp.setVendor("fineract");

      provisionerService.api().createApplication(horusApp);

      final AssignedApplication horusAssigned = new AssignedApplication();
      horusAssigned.setName(officeClient.name());

      provisionerService.api().assignApplications(tenant.getIdentifier(), Collections.singletonList(horusAssigned));

      Thread.sleep(700L); //TODO: replace this with an event listener.

      return isisAdminPassword.getAdminPassword();
    }
  }

  private static String encodePassword(final String password) {
    return Base64Utils.encodeToString(password.getBytes());
  }

  private Tenant makeTenant() {
    final Tenant tenant = new Tenant();
    tenant.setName("dudette");
    tenant.setIdentifier(TEST_TENANT);
    tenant.setDescription("oogie boogie woman");

    final CassandraConnectionInfo cassandraConnectionInfo = new CassandraConnectionInfo();
    cassandraConnectionInfo.setClusterName("Test Cluster");
    cassandraConnectionInfo.setContactPoints("127.0.0.1:9142");
    cassandraConnectionInfo.setKeyspace("comp_test");
    cassandraConnectionInfo.setReplicas("3");
    cassandraConnectionInfo.setReplicationType("Simple");
    tenant.setCassandraConnectionInfo(cassandraConnectionInfo);

    final DatabaseConnectionInfo databaseConnectionInfo = new DatabaseConnectionInfo();
    databaseConnectionInfo.setDriverClass("org.mariadb.jdbc.Driver");
    databaseConnectionInfo.setDatabaseName("comp_test");
    databaseConnectionInfo.setHost("localhost");
    databaseConnectionInfo.setPort("3306");
    databaseConnectionInfo.setUser("root");
    databaseConnectionInfo.setPassword("mysql");
    tenant.setDatabaseConnectionInfo(databaseConnectionInfo);
    return tenant;
  }

  private Role makeOfficeAdministratorRole() {
    final Permission employeeCreationPermision = new Permission();
    employeeCreationPermision.setAllowedOperations(AllowedOperation.ALL);
    employeeCreationPermision.setPermittableEndpointGroupIdentifier(io.mifos.office.api.v1.PermittableGroupIds.EMPLOYEE_MANAGEMENT);

    final Permission officeCreationPermision = new Permission();
    officeCreationPermision.setAllowedOperations(AllowedOperation.ALL);
    officeCreationPermision.setPermittableEndpointGroupIdentifier(io.mifos.office.api.v1.PermittableGroupIds.OFFICE_MANAGEMENT);

    final Permission userCreationPermission = new Permission();
    userCreationPermission.setAllowedOperations(Collections.singleton(AllowedOperation.CHANGE));
    userCreationPermission.setPermittableEndpointGroupIdentifier(io.mifos.identity.api.v1.PermittableGroupIds.IDENTITY_MANAGEMENT);

    final Role role = new Role();
    role.setIdentifier("office_administrator");
    role.setPermissions(Arrays.asList(employeeCreationPermision, officeCreationPermision, userCreationPermission));

    return role;
  }

  private Role makeEmployeeRole() {
    final Set<AllowedOperation> noDeleteOperation = new HashSet<>();
    noDeleteOperation.add(AllowedOperation.CHANGE);
    noDeleteOperation.add(AllowedOperation.READ);

    final Permission employeeSelfPermission = new Permission();
    employeeSelfPermission.setAllowedOperations(noDeleteOperation);
    employeeSelfPermission.setPermittableEndpointGroupIdentifier(io.mifos.office.api.v1.PermittableGroupIds.SELF_MANAGEMENT);

    final Role role = new Role();
    role.setIdentifier("employee");
    role.setPermissions(Collections.singletonList(employeeSelfPermission));
    return role;
  }
}
