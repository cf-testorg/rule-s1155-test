package com.restoratio.monaco.ruletest.squid.compliant;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.api.client.repackaged.org.apache.commons.codec.binary.Base64;
import com.google.common.collect.Maps;
import com.google.common.net.HttpHeaders;
import com.streamonce.configuration.security.SdkManagementUserDetailsService;
import com.streamonce.connectors.jive.JiveOAuthService;
import com.streamonce.core.email.EmailUtil;
import com.streamonce.core.service.AllowedSDKUserService;
import com.streamonce.core.service.DevelopmentTeamService;
import com.streamonce.core.service.ExternalConnectorEntityService;
import com.streamonce.core.service.RegistryService;
import com.streamonce.core.service.ServerConfigService;
import com.streamonce.core.service.UsageService;
import com.streamonce.core.service.UserSystemConfigurationService;
import com.streamonce.dto.SystemTypeV2;
import com.streamonce.dto.UsageData;
import com.streamonce.model.AllowedSDKUser;
import com.streamonce.model.DevelopmentTeam;
import com.streamonce.model.ExternalConnectorEntity;
import com.streamonce.s3.S3Service;
import com.streamonce.sdk.framework.ExternalEndpointInvoker;
import com.streamonce.sdk.framework.RemoteEnvironmentCallService;
import com.streamonce.sdk.loader.ExternalConnectorPackage;
import com.streamonce.sdk.loader.ExternalConnectorPackageInventoryService;
import com.streamonce.sdk.loader.ExternalConnectorPackageItem;
import com.streamonce.sdk.loader.ExternalConnectorPackageWithEntity;
import com.streamonce.sdk.loader.ExternalConnectorPolicy;
import com.streamonce.sdk.loader.ExternalConnectorService;
import com.streamonce.sdk.loader.ExternalJarValidationContext;
import com.streamonce.sdk.loader.ExternalPermissionsService;
import com.streamonce.sdk.loader.PermissionsJsonHelper;
import com.streamonce.sdk.security.model.ConnectorPermission;
import com.streamonce.sdk.security.model.ConnectorPermissions;
import com.streamonce.sdk.v1.common.AddonDefinition;
import com.streamonce.sdk.v1.tile.TileDescriptor;
import com.streamonce.util.JiveUtils;
import com.streamonce.web.configuration.ExternalStorageConnectorConfig;
import com.streamonce.web.external.auth.ExternalConnectorAuthenticationService;
import com.streamonce.web.jive.JiveTileContainerMap;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.Policy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.annotation.Nonnull;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;
import org.springframework.web.multipart.commons.CommonsMultipartResolver;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Created with IntelliJ IDEA.
 * User: yuval.twig
 * Date: 04/03/2014
 * Time: 11:55
 * To change this template use File | Settings | File Templates.
 */
@Slf4j
@Controller
@RequestMapping(value = "/external/connector")
public class ExternalConnectorEndpoint {

    public static final String CONTENT_DISPOSITION = "Content-Disposition";

    //URL patterns for remote management calls to remote environments (e.g. pro/preprod etc.)
    private static final String remoteManagementUrl = "https://{0}/external/connector/remote/manage";
    private static final String remoteEnableConnectorUrl = "https://{0}/external/connector/remote/enable/{1}";
    private static final String remotePermissionsUrl = "https://{0}/external/connector/remote/permissions/{1}";
    private static final String remoteAddonUrl = "https://{0}/external/connector/remote/addon/{1}";
    private static final String remoteAddOnMac = "https://{0}/external/connector/remote/macaddon/{1}";
    private final static String REDIRECT_REFRESH_POLICY = "{0}://{1}/external/connector/redirect/permissions/refresh/{2}";
    private static final String remoteUsageUrl = "https://{0}/external/connector/remote/{1}/usage";

    private static final String folderId ="folderId";

    public static final String COMMUNITY_EMAIL_ADDRESS = "COMMUNITY_EMAIL_ADDRESS";
    public static final String PARAM_JIVE_URL = "jive_url";
    public static final String JIVE_EXTN = "JiveEXTN ";
    public static final String INSTANCE_ID_HEADER = "x-tile-instance-id";
    public static final String ICON_16_PNG = "icon_16.png";
    public static final String ICON_48_PNG = "icon_48.png";


    @Autowired
    ExternalConnectorService externalConnectorService;

    @Autowired
    ExternalConnectorEntityService externalConnectorEntityService;

    @Autowired
    ExternalConnectorPackageInventoryService externalConnectorPackageInventoryService;

    @Autowired
    ServerConfigService serverConfigService;

    @Autowired
    private UsageService usageService;

    @Autowired
    private EmailUtil emailUtil;

    @Autowired
    private ExternalConnectorAuthenticationService externalConnectorAuthenticationService;

    @Autowired
    private AbstractRememberMeServices rememberMeService;

    @Autowired
    private AllowedSDKUserService allowedSDKUserService;

    @Autowired
    private SdkManagementUserDetailsService sdkManagementUserDetailsService;

    @Autowired
    private ExternalPermissionsService externalPermissionsService;

    @Autowired
    private RemoteEnvironmentCallService remoteEnvironmentCallService;

    @Autowired
    private JiveTileContainerMap jiveTileContainerMap;

    @Autowired
    private RegistryService registryService;

    @Autowired
    ServletContext servletContext;

    @Autowired
    private DevelopmentTeamService developmentTeamService;

    @Autowired
    private UserSystemConfigurationService userSystemConfigurationService;

    @Autowired
    private ExternalEndpointInvoker externalRequestInvoker;

    @Autowired
    private S3Service s3;

    @RequestMapping(value = "/", method = {RequestMethod.GET})
    public String getExternalConnectorPage(HttpSession session, Model model, Authentication authentication)
            throws IOException
    {
        if (!isSdkEndPointEnabled()) {
            return "sdkDefaultHomePage";
        }
        String email = getEmailFromSession(session);
        if (email != null) {
            boolean hasConnectors = externalConnectorPackageInventoryService.userHasConnectors(email);
            return hasConnectors || remoteEnvironmentCallService.isAdmin(authentication) ?
                    getExternalConnectorManagePage(session, model, authentication,
                            RemoteEnvironmentCallService.EnvTypes.sandbox.getName()) :
                    getExternalConnectorGettingStartedPage(session, model);
        }

        model.addAttribute("soServer", serverConfigService.getServerURLSSL());

        return "externalConnector";
    }

    @RequestMapping(value = "/validateJiveCommunityUser/{activationCode}", method = RequestMethod.GET)
    public void validateJiveCommunityUser(HttpServletRequest request, HttpServletResponse response,
                                          @PathVariable String activationCode)
    {
        final ObjectNode responseJson = new ObjectNode(JsonNodeFactory.instance);
        ObjectMapper mapper = new ObjectMapper();

        try {
            ExternalConnectorAuthenticationService.UserWithToken userAndToken = externalConnectorAuthenticationService
                    .authenticateInJiveUsingActivationCode(
                            activationCode);
            JiveOAuthService.JiveUserContainer myUser = userAndToken.getUser();

            allowedSDKUserService.addUserIfNotExists(myUser.email);

            boolean hasConnectors = externalConnectorPackageInventoryService.userHasConnectors(myUser.email);
            responseJson.put("hasConnectors", hasConnectors);
            responseJson.put("email", myUser.email);
            responseJson.put("userId", myUser.id);
            if (StringUtils.isNotEmpty(myUser.displayName) && myUser.displayName.contains(" ")) {
                responseJson.put("firstName", myUser.displayName.substring(0, myUser.displayName.indexOf(" ")));
                responseJson.put("lastName", myUser.displayName
                        .substring(myUser.displayName.indexOf(" ") + 1, myUser.displayName.length()));
            }

            if (hasConnectors) {
                ObjectNode connectors = mapper.createObjectNode();
                try {
                    fillConnectorsListForUser(myUser.email, mapper, connectors);
                }
                catch (Exception e) {
                    log.error("failed to load connector list", e);
                }

                responseJson.set("connectors", connectors);
            }
            allowedSDKUserService.setAccessToken(userAndToken.getUser().email, userAndToken.getAccessToken());
            initSessionSecurityAttributes(request, response, userAndToken);
            writeResponse(response, mapper.writeValueAsString(responseJson));
        }
        catch (Exception e) {
            log.error("Failed to authenticate Jive Community user", e);
            writeResponse(response, "{\"error\":\"" + e.getMessage() + "\"}");
        }

    }

    private void initSessionSecurityAttributes(final HttpServletRequest request, HttpServletResponse response,
                                               ExternalConnectorAuthenticationService.UserWithToken userWithToken)
    {
        UserDetails user = sdkManagementUserDetailsService.loadUserByUsername(userWithToken.getUser().email);
        Authentication auth = new RememberMeAuthenticationToken(userWithToken.getUser().email, user,
                user.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(auth);
        HttpSession session = request.getSession(true);
        session.setAttribute(COMMUNITY_EMAIL_ADDRESS, userWithToken.getUser().email);
        session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

        //simulating a request with check box selected for remember-me service
        HttpServletRequestWrapper wrapper = new HttpServletRequestWrapper(request) {
            @Override
            public String getParameter(String name) {
                return "true";
            }
        };

        rememberMeService.loginSuccess(wrapper, response, auth);
    }

    private void writeResponse(HttpServletResponse response, String error) {
        try {
            response.getWriter().print(error);
            response.getWriter().flush();
        }
        catch (IOException e) {
            log.error("Failed to get writer", e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    @RequestMapping(value = "/logout", method = {RequestMethod.GET})
    public String logoutExternalConnector(HttpServletRequest request, HttpServletResponse response) {
        rememberMeService.logout(request, response, SecurityContextHolder.getContext().getAuthentication());
        return "redirect:/logout";
    }

    @RequestMapping(value = "/edit/{type}", method = {RequestMethod.GET})
    public String updateConnector(HttpSession session, Model model, @PathVariable String type) throws IOException
    {
        initUploadModel(session, model);
        ExternalConnectorPackageWithEntity externalConnector = externalConnectorPackageInventoryService
                .getPackageWithEntity(type);

        if (externalConnector != null) {
            model.addAttribute("connectorType", type);
            String icon = getBase64EncodedIcon(type, "16");
            if (icon != null && icon.length() > 0) {
                model.addAttribute("icon16", icon);
            }
            icon = getBase64EncodedIcon(type, "48");
            if (icon != null && icon.length() > 0) {
                model.addAttribute("icon48", icon);
            }
            icon = getBase64EncodedIcon(type, "128");
            if (icon != null && icon.length() > 0) {
                model.addAttribute("icon128", icon);
            }
        }
        return "externalConnector";
    }

    @RequestMapping(value = "/upload", method = {RequestMethod.GET})
    public String uploadConnector(HttpSession session, Model model) throws IOException {
        initUploadModel(session, model);
        return "externalConnector";
    }

    private void initUploadModel(HttpSession session, Model model) {
        String email = getEmailFromSession(session);

        // Used to determine whether to show "terms agreement" check box
        model.addAttribute("hasConnectors", (externalConnectorPackageInventoryService.userHasConnectors(email)));
        model.addAttribute("soServer", serverConfigService.getServerURLSSL());
        model.addAttribute("tab", "upload");
    }

    private boolean isSdkEndPointEnabled() {
        return serverConfigService.isSdkEndPointEnabled();
    }

    private int getUserConnectorCount(String email) {
        return externalConnectorPackageInventoryService.getUserPackages(email).size();
    }

    private int getUserConnectorCountIgnoreDeleted(String email) {
        int count = 0;
        List<ExternalConnectorPackageWithEntity> userPackages =  externalConnectorPackageInventoryService.getUserPackages(email);

        for (ExternalConnectorPackageWithEntity externalConnectorPackageWithEntity : userPackages) {
            if (externalConnectorPackageWithEntity.getStatus() !=  ExternalConnectorEntity.Status.Deleted) {
                count++;
            }
        }

        return count;
    }

    @RequestMapping(value = "/enable/{connectorType}", method = {RequestMethod.PUT})
    @ResponseBody
    public String enableConnector(HttpServletRequest request, Authentication authentication,
                                  @PathVariable String connectorType,
                                  @RequestParam(value = "env", defaultValue = "sandbox") String environment)
    {
        if (!remoteEnvironmentCallService.isValidEnvironment(environment)) {
            return "Cannot enable connector " + connectorType + ". Invalid environment: " + environment;
        }
        if (!RemoteEnvironmentCallService.EnvTypes.isSandbox(environment)) {
            boolean isAdmin = remoteEnvironmentCallService.isAdmin(authentication);
            try {
                String response = remoteEnvironmentCallService
                        .callRemoteContent(null, getEmailFromSession(request.getSession()),
                                isAdmin, environment,
                                HttpMethod.PUT, remoteEnableConnectorUrl, connectorType);
                return response == null ? "Failed to enable " + connectorType + " on environment " +
                        environment : response;
            }
            catch (RestClientException e) {
                String message =
                        "Failed to enable " + connectorType + " on environment " + environment + ". " + e.toString();
                log.error(message, e);
                return message;
            }
        }
        else {
            return enableConnectorLocally(connectorType);
        }
    }

    @RequestMapping(value = "/remote/enable/{connectorType}", method = {RequestMethod.PUT})
    @ResponseBody
    public String enableConnectorLocally(@PathVariable String connectorType) {
        ExternalConnectorPackageWithEntity connectorEntity = externalConnectorPackageInventoryService
                .getPackageWithEntity(
                        connectorType);
        if (connectorEntity == null) {
            return "Connector " + connectorType + " not found";
        }
        if (connectorEntity.getStatus() != ExternalConnectorEntity.Status.Disabled) {
            return "Connector " + connectorType + " has a status of " + connectorEntity.getStatus() +
                    ". Only Disabled connectors can be enabled.";
        }
        try {
            externalConnectorService.enableExternalConnector(connectorEntity.getPackageSystemTypeV2());
            return "success";
        }
        catch (Exception e) {
            String message = "Failed to enable connector. " + e.toString();
            log.error(message, e);
            return message;
        }
    }

    @RequestMapping(value = "/delete/{type}", method = {RequestMethod.GET})
    public String deleteConnector(HttpSession session, Model model, @PathVariable String type) throws IOException {
        try {
            log.info( "got request to delete connector " + type);
            //do not delete from DB unless unused and not promoted
            final ExternalConnectorPackageWithEntity packageWithEntity = externalConnectorPackageInventoryService
                    .getPackageWithEntity(type);
            final boolean hasUserSysConfs = !userSystemConfigurationService
                    .isSystemTypeUnused(packageWithEntity.getPackageSystemTypeV2());
            //For Sandbox environments, that have remote environments controlled via the management page, a connector
            // can exist on one of the remote environments and if so should not be deleted from the DB.
            // For production environments (which are not sandbox), there are no remote environments
            final boolean existsOnRemoteEnvs =
                    serverConfigService.isSdkEndPointEnabled() && remoteEnvironmentCallService
                            .isConnectorPromoted(type, getEmailFromSession(session));
            final boolean keepInDB = hasUserSysConfs || existsOnRemoteEnvs;
            log.info(
                    "System type " + type + " is " + (hasUserSysConfs ? "BEING USED" : "UNUSED") + " and " +
                            (existsOnRemoteEnvs ? "PROMOTED" : "NOT PROMOTED") + " and therefore will be " +
                            (keepInDB ? "KEPT IN DB" : "REMOVED FROM DB"));
            externalConnectorService.deleteConnectorIfUnused(type, keepInDB);
            model.addAttribute("success", "Connector with type '" + type + "' was deleted.");
        }
        catch (Exception e) {
            log.error("Error deleting external connector", e);
            throw e;
        }
        return "redirect:/external/connector/manage";
    }

    @RequestMapping("/remote/exists/{connectorType}")
    @ResponseBody
    public boolean isConnectorExists(@PathVariable String connectorType) {
        return externalConnectorPackageInventoryService.isSystemTypeExists(connectorType);
    }


    @RequestMapping(value = "/promote/{type}", method = {RequestMethod.POST})
    public String promoteConnector(HttpSession session, @PathVariable String type, @RequestBody String notesAttribute,
                                   RedirectAttributes redirectAttributes) throws IOException
    {
        String email = getEmailFromSession(session);
        notesAttribute = notesAttribute.replace("connector-extra-details=", "");
        String jarPath = externalConnectorService.getExternalConnectorsPath() + File.separatorChar + type + ".jar";
        boolean result = false;
        try {
            notesAttribute = URLDecoder.decode(notesAttribute, "UTF-8");
            result = emailUtil.sendExternalConnectorPromoteEmail(type, notesAttribute, jarPath, email);
        }
        catch (Exception e) {
            log.error("Error during promote to production for connector " + type + " and user " + email, e);
        }

        if (result) {
            redirectAttributes.addFlashAttribute("success",
                    "Your request to promote " + type +
                            " connector to production submitted successfully. We will notify you on the review status via e-mail (" +
                            email + ")");
        }
        else {
            redirectAttributes.addFlashAttribute("error",
                    "We couldn't process your request at this time, please try again latter or contact our support via so_sdk@jivesoftware.com");
        }


        return "redirect:/external/connector/manage";
    }

    @RequestMapping(value = "/manage", method = {RequestMethod.GET})
    public String getExternalConnectorManagePage(HttpSession session, Model model, Authentication authentication,
                                                 @RequestParam(
                                                         value = "env", defaultValue = "sandbox") String environment)
            throws IOException
    {
        ObjectMapper mapper = new ObjectMapper();
        try {
            boolean isAdmin = remoteEnvironmentCallService.isAdmin(authentication);
            JsonNode remoteContent = null;
            String remoteBody;
            //if the environment doesn't exist revert back to sandbox and add an error for the UI
            if (!remoteEnvironmentCallService.isValidEnvironment(environment)) {
                model.addAttribute("envError", "Invalid environment: " + environment);
                environment = RemoteEnvironmentCallService.EnvTypes.sandbox.getName();
            }
            if (!RemoteEnvironmentCallService.EnvTypes.isSandbox(environment)) {
                try {
                    //send the connector types that should be fetched from the remote system based on their state in the sandbox
                    List<ExternalConnectorPackageWithEntity> connectorsForUser = externalConnectorPackageInventoryService
                            .getUserPackagesIncludingTeam(
                                    getEmailFromSession(session));
                    List<String> connectorTypes = new ArrayList<>();
                    for (ExternalConnectorPackageWithEntity connectorEntity : connectorsForUser) {
                        connectorTypes.add(connectorEntity.getSubSystemType());
                    }
                    remoteBody = remoteEnvironmentCallService
                            .callRemoteContent(connectorTypes, getEmailFromSession(session),
                                    isAdmin, environment,
                                    HttpMethod.POST, remoteManagementUrl
                            );
                    if (remoteBody == null) {
                        String error =
                                "Failed to get proper response from remote environment - " + environment;
                        log.error(error);
                        model.addAttribute("envError", error);
                        environment = RemoteEnvironmentCallService.EnvTypes.sandbox.getName();
                    }
                    else {
                        remoteContent = mapper.readTree(remoteBody);
                    }
                }
                catch (Exception e) {
                    String error =
                            "Failed to get proper response from remote environment - " + environment + ": " +
                                    e.toString();
                    log.error(error, e);
                    model.addAttribute("envError", error);
                    environment = RemoteEnvironmentCallService.EnvTypes.sandbox.getName();
                }
            }
            String email = getEmailFromSession(session);
            ObjectNode rootNode = mapper.createObjectNode();
            //if succeeded in getting remote response set the connectors to be the ones from the remote environment
            model.addAttribute("isAdmin", isAdmin);
            if (remoteContent != null) {
                model.addAttribute("connectors", remoteContent.get("connectors"));
            }
            else {
                //otherwise fill the model with connectors from the current environment
                if (isAdmin) {
                    //get all the connectors regardless of user
                    fillConnectorsListForAdmin(mapper, rootNode);
                }
                else {
                    //get the connectors for the user
                    fillConnectorsListForUser(email, mapper, rootNode);
                }
                if (rootNode.size() > 0) {
                    model.addAttribute("connectors", rootNode);
                }
            }
            model.addAttribute("userTeams", getUserTeams(mapper, email));
            ArrayNode envTypes = getEnvTypes(mapper);
            model.addAttribute("envTypes", envTypes);
            model.addAttribute("selectedEnv", environment);
            model.addAttribute("tab", "manage");
            model.addAttribute("soServer", serverConfigService.getServerURLSSL());
            model.addAttribute("isSandbox", remoteContent == null && isSdkEndPointEnabled());
            model.addAttribute("userConnectorCount",
                    remoteContent == null ? getUserConnectorCount(email) : remoteContent.get("userConnectorCount")
                            .intValue());
            model.addAttribute("maxConnectorCount", externalConnectorService.getMaxConnectorsPerUser());
            model.addAttribute("externalConnectorTimeToLive",
                    externalConnectorService.getExternalConnectorTimeToLive());
        }
        catch (Exception e) {
            log.error("Error while loading management page", e);
            throw e;
        }
        return "externalConnector";
    }

    /**
     * Gets the teams for a specific user which are all the teams the user is a member of
     *
     * @param mapper for json operations
     * @param email  of the user for which the teams are fetched
     * @return
     */
    private ArrayNode getUserTeams(ObjectMapper mapper, String email) {
        List<DevelopmentTeam> userTeams = developmentTeamService.getUserTeams(email);
        return convertTeamListToJson(mapper, userTeams);
    }

    private ArrayNode convertTeamListToJson(ObjectMapper mapper, List<DevelopmentTeam> userTeams) {
        ArrayNode teams = mapper.createArrayNode();
        for (DevelopmentTeam userTeam : userTeams) {
            ObjectNode team = mapper.createObjectNode();
            team.put("id", userTeam.getId());
            team.put("name", userTeam.getName());
            team.put("createdBy", userTeam.getCreateByEmail());
            team.set("connectors", getTeamConnectorsJson(mapper, userTeam));
            ArrayNode members = getTeamMembersJson(mapper, userTeam);
            team.set("members", members);
            teams.add(team);
        }
        return teams;
    }

    private ArrayNode getTeamMembersJson(ObjectMapper mapper, DevelopmentTeam userTeam) {
        ArrayNode members = mapper.createArrayNode();
        for (AllowedSDKUser allowedSDKUser : userTeam.getMembers()) {
            members.add(allowedSDKUser.getEmail());
        }
        return members;
    }

    private ArrayNode getTeamConnectorsJson(ObjectMapper mapper, DevelopmentTeam userTeam) {
        Map<String, String> connectorToTeamMap = developmentTeamService.getConnectorToTeamMap();
        ArrayNode connectors = mapper.createArrayNode();
        for (ExternalConnectorEntity connectorEntity : userTeam.getConnectors()) {
            String type = connectorEntity.getSubSystemType();
            ExternalConnectorPackage connectorPackage = externalConnectorPackageInventoryService
                    .getPackage(type);
            ObjectNode connectorJson = mapper.createObjectNode();
            connectorJson.put("connectorType", type);
            connectorJson.put("displayName", connectorPackage.getDisplayName());
            connectorJson.put("owner", connectorPackage.getOwnerEmail());
            connectorJson.put("team", connectorToTeamMap.get(type));
            connectors.add(connectorJson);
        }
        return connectors;
    }

    public ArrayNode getEnvTypes(ObjectMapper mapper) {
        ArrayNode envTypes = mapper.createArrayNode();
        for (RemoteEnvironmentCallService.EnvTypes envType : RemoteEnvironmentCallService.EnvTypes
                .getEnvironments())
        {
            ObjectNode env = mapper.createObjectNode();
            env.put("id", envType.getName());
            env.put("displayName", envType.getDisplayName());
            envTypes.add(env);
        }
        return envTypes;
    }

    /**
     * Entry point for non-sandbox to get the connectors information
     * <p/>
     * The method is a POST method because it accepts a request body
     *
     * @param session
     * @param authentication
     * @return a properties map containing information from the local environment with all connectors
     * @throws IOException
     */
    @RequestMapping(value = "/remote/manage", method = {RequestMethod.POST},
            produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map getRemoteExternalConnectorManagePage(@RequestBody List<String> connectorTypes, HttpSession session,
                                                    Authentication authentication)
            throws IOException
    {
        Map<String, Object> properties = new HashMap<>();
        ObjectMapper mapper = new ObjectMapper();
        try {
            boolean isAdmin = remoteEnvironmentCallService.isAdmin(authentication);
            String email = getEmailFromSession(session);
            ObjectNode rootNode = mapper.createObjectNode();
            if (isAdmin) {
                fillConnectorsListForAdmin(mapper, rootNode);
                properties.put("isAdmin", true);
            }
            else {
                fillConnectorsListForRemoteUser(mapper, rootNode, connectorTypes);
            }

            if (rootNode.size() > 0) {
                properties.put("connectors", rootNode);
            }

            properties.put("userConnectorCount", getUserConnectorCount(email));
        }
        catch (Exception e) {
            log.error("Error while loading management page", e);
            throw e;
        }
        return properties;
    }

    /**
     * Endpoint for getting the permissions of a specific connector from current environment or from a remote one
     *
     * @param session
     * @param authentication
     * @param connectorType
     * @param env
     * @return
     */
    @RequestMapping(value = "/permissions/{connectorType}", method = {RequestMethod.GET})
    @ResponseBody
    public String getPermissions(HttpSession session, Authentication authentication,
                                 @PathVariable("connectorType") String connectorType,
                                 @RequestParam(value = "env", defaultValue = "sandbox") String env)
    {
        if (!RemoteEnvironmentCallService.EnvTypes.isSandbox(env)) {
            return remoteEnvironmentCallService.callRemoteContent(null, getEmailFromSession(session),
                    remoteEnvironmentCallService.isAdmin(authentication), env,
                    HttpMethod.GET, remotePermissionsUrl, connectorType);
        }
        else {
            return getPermissionsLocally(connectorType);
        }

    }

    /**
     * Get the permissions for a connector on the current environment
     *
     * @param connectorType
     * @return
     */
    @RequestMapping(value = "/remote/permissions/{connectorType}", method = {RequestMethod.GET})
    @ResponseBody
    public String getPermissionsLocally(@PathVariable("connectorType") String connectorType) {
        //call the secured method that is allowed on ly for admins
        return externalPermissionsService
                .getExternalConnectorPermissionsJsonSecured(connectorType);
    }

    /**
     * Update the permissions on the current environment or on a remote one
     *
     * @param request
     * @param authentication
     * @param connectorType
     * @param updatedPermissions
     * @param env
     * @return
     */
    @RequestMapping(value = "/permissions/{connectorType}", method = {RequestMethod.PUT},
            consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public boolean updatePermissions(HttpServletRequest request, Authentication authentication,
                                     @PathVariable("connectorType") String connectorType,
                                     @RequestBody List<ConnectorPermission> updatedPermissions,
                                     @RequestParam(value = "env", defaultValue = "sandbox") String env)
    {
        if (!RemoteEnvironmentCallService.EnvTypes.isSandbox(env)) {
            String remoteResponse = remoteEnvironmentCallService.callRemoteContent(updatedPermissions,
                    getEmailFromSession(request.getSession()), remoteEnvironmentCallService.isAdmin(authentication),
                    env,
                    HttpMethod.PUT, remotePermissionsUrl, connectorType);
            return Boolean.valueOf(remoteResponse);
        }
        else {
            return updatePermissionsLocally(connectorType, updatedPermissions, request);
        }
    }

    /**
     * Update permissions on the current environment
     *
     * @param connectorType
     * @param updatedPermissions
     * @param request
     * @return
     */
    @RequestMapping(value = "/remote/permissions/{connectorType}", method = {RequestMethod.PUT},
            consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public boolean updatePermissionsLocally(@PathVariable("connectorType") String connectorType,
                                            @RequestBody List<ConnectorPermission> updatedPermissions,
                                            HttpServletRequest request)
    {
        try {
            //call the secured method that is allowed on ly for admins
            externalPermissionsService.updateConnectorPermissions(connectorType, updatedPermissions);
            String filePath = serverConfigService.getExternalConnectorsPath() + "/" +connectorType + ".per";
            Files.newBufferedWriter(Paths.get(filePath)).close();
            return true;
        }
        catch (Exception e) {
            log.error("Failed to create Json for connector " + connectorType + " with permissions " +
                    updatedPermissions, e);
            return false;
        }
    }

    /**
     * Refresh permissions on the current environment for a connector type or all if no connector type supplied
     *
     * @param connectorType to refresh. If empty will reset all the policy cache
     * @return
     */
    @RequestMapping(value = "/redirect/permissions/refresh/{connectorType}", method = {RequestMethod.GET})
    @ResponseBody
    public boolean refreshPermissions(@PathVariable("connectorType") String connectorType) {
        try {
            if (StringUtils.trimToNull(connectorType) == null) {
                Policy.getPolicy().refresh();
            }
            else {
                ((ExternalConnectorPolicy) Policy.getPolicy()).refresh(connectorType);
            }
            return true;
        }
        catch (Exception e) {
            log.error("Failed to refresh connector " + connectorType, e);
            return false;
        }
    }

    @RequestMapping(value = "/gettingstarted", method = {RequestMethod.GET})
    public String getExternalConnectorGettingStartedPage(HttpSession session, Model model) throws IOException {
        model.addAttribute("tab", "gettingstarted");
        model.addAttribute("soServer", serverConfigService.getServerURLSSL());
        return "externalConnector";
    }

    /**
     * Fill the list of connectors for a specific user
     *
     * @param email    of the user
     * @param mapper   to create nodes
     * @param rootNode the node that holds all the connector nodes
     */
    private void fillConnectorsListForUser(String email, ObjectMapper mapper, ObjectNode rootNode) {
        List<ExternalConnectorPackageWithEntity> userPackages = externalConnectorPackageInventoryService
                .getUserPackagesIncludingTeam(
                        email);
        fillConnectorsList(mapper, rootNode, userPackages);
    }

    /**
     * Fill the list of connectors for an admin which contains the data for all the connectors
     *
     * @param mapper   to create nodes
     * @param rootNode the node that holds all the connector nodes
     */
    private void fillConnectorsListForAdmin(ObjectMapper mapper, ObjectNode rootNode) {
        List<ExternalConnectorPackageWithEntity> usersConnectors = externalConnectorPackageInventoryService
                .getAllPackagesWithEntities();
        fillConnectorsList(mapper, rootNode, usersConnectors);
    }

    /**
     * Fill the list of connectors for an user which contains the data for the selected connectors
     *
     * @param mapper         to create nodes
     * @param rootNode       the node that holds all the connector nodes
     * @param connectorTypes the types to look for
     */
    private void fillConnectorsListForRemoteUser(ObjectMapper mapper, ObjectNode rootNode,
                                                 List<String> connectorTypes)
    {
        List<ExternalConnectorPackageWithEntity> usersConnectors;
        if (connectorTypes == null || connectorTypes.isEmpty()) {
            return;
        }
        usersConnectors = externalConnectorPackageInventoryService.getPackagesWithEntities(connectorTypes);
        Collections.sort(usersConnectors, new Comparator<ExternalConnectorPackage>() {
            @Override
            public int compare(ExternalConnectorPackage o1, ExternalConnectorPackage o2) {
                return o1.getDisplayName().compareToIgnoreCase(o2.getDisplayName());
            }
        });
        fillConnectorsList(mapper, rootNode, usersConnectors);
    }

    /**
     * use either {@link #fillConnectorsListForUser(String, ObjectMapper, ObjectNode)}
     * or {@link #fillConnectorsListForAdmin(ObjectMapper, ObjectNode)}
     *
     * @param mapper          to create nodes
     * @param rootNode        the node that holds all the connector nodes
     * @param usersConnectors
     */
    private void fillConnectorsList(ObjectMapper mapper, ObjectNode rootNode,
                                    List<ExternalConnectorPackageWithEntity> usersConnectors)
    {
        Map<String, String> connectorToTeamMap = developmentTeamService.getConnectorToTeamMap();
        ObjectNode node;
        for (ExternalConnectorPackageWithEntity connectorPackage : usersConnectors) {
            node = mapper.createObjectNode();
            ObjectNode typesNode = getTypes(mapper, connectorPackage);
            if (typesNode != null) {
                node.set("types", typesNode);
            }
            //check if the current environment has log files for the connector
            File logFile = new File(
                    externalConnectorService.getExternalConnectorsPath() + File.separator + "logs" + File.separator +
                            connectorPackage.getSubSystemType() + ".log");
            node.put("hasLogs", logFile.exists() && logFile.length() > 0);
            long lastModified = logFile.lastModified();
            node.put("logsLastModified", lastModified == 0l ? "" : new Date(lastModified).toString());
            node.put("name", connectorPackage.getDisplayName());
            node.put("team", connectorToTeamMap.get(connectorPackage.getSubSystemType()));
            node.put("description", connectorPackage.getDescription());
            ExternalConnectorPackageItem.Type type = connectorPackage.getMainType();
            node.put("type", String.valueOf(type));
            node.put("status", connectorPackage.getStatus().toString());
            ConnectorPermissions connectorPermissions = getConnectorPermissions(connectorPackage.getSubSystemType());
            node.put("isManagePermissions",
                    connectorPermissions != null && !connectorPermissions.getPermissions().isEmpty());
            ArrayNode unauthorisedPermissions = getUnauthorisedPermissions(mapper, connectorPermissions);
            if (unauthorisedPermissions != null) {
                node.set("unauthorisedPermissions", unauthorisedPermissions);
            }
            if (connectorPackage.isEnabled()) {
                node.put("health", unauthorisedPermissions == null ? "ok" : "warning");
            }
            else if (connectorPackage.isDisabled()) {
                node.put("health", "error");
            }
            node.put("statusMessage", connectorPackage.getStatusMessage());
            node.put("version", connectorPackage.getVersion());
            String ownerEmail = connectorPackage.getOwnerEmail();
            node.put("owner", ownerEmail);
            node.put("supportEmail", connectorPackage.getSupportEmail());
            node.set("ownerTeams", getUserTeams(mapper, ownerEmail));
            rootNode.set(connectorPackage.getSubSystemType(), node);
        }
//        }
    }

    private ObjectNode getTypes(ObjectMapper mapper, ExternalConnectorPackageWithEntity connectorPackage) {
        Set<String> gauges = new HashSet<>();
        Set<String> lists = new HashSet<>();
        Set<String> tables = new HashSet<>();
        Set<String> streams = new HashSet<>();
        Set<String> exporters = new HashSet<>();
        Set<String> calendars = new HashSet<>();
        Set<String> apps = new HashSet<>();
        for (ExternalConnectorPackageItem packageItem : connectorPackage.getAllItems()) {
            switch (packageItem.getType()) {
                case STREAM_INTEGRATION:
                    streams.add(packageItem.getDisplayName());
                    break;
                case EXPORTER:
                    exporters.add(packageItem.getDisplayName());
                    break;
                case STORAGE:
                    break;
                case TILE:
                    switch (packageItem.getTileStyle()) {
                        case GAUGE:
                            gauges.add(packageItem.getDisplayName());
                            break;
                        case LIST:
                            lists.add(packageItem.getDisplayName());
                            break;
                        case TABLE:
                            tables.add(packageItem.getDisplayName());
                            break;
                        case CALENDAR:
                            calendars.add(packageItem.getDisplayName());
                            break;
                        default:
                            break;
                    }
                    break;
                case APP:
                    apps.add(packageItem.getDisplayName());
                    break;
                default:                    
                    break;
            }
        }
        if (gauges.isEmpty() && lists.isEmpty() && tables.isEmpty() && calendars.isEmpty() && exporters.isEmpty() && apps.isEmpty()) {
            return null;
        }
        ObjectNode typesNode = mapper.createObjectNode();
        addType(mapper, gauges, typesNode, "gauges");
        addType(mapper, lists, typesNode, "lists");
        addType(mapper, streams, typesNode, "streams");
        addType(mapper, exporters, typesNode, "exporters");
        addType(mapper, tables, typesNode, "tables");
        addType(mapper, calendars, typesNode, "calendars");
        addType(mapper, apps, typesNode, "apps");
        return typesNode;
    }

    private void addType(ObjectMapper mapper, Set<String> tileNames, ObjectNode typesNode, String typeName) {
        ArrayNode arrayNode = mapper.createArrayNode();
        for (String tileName : tileNames) {
            arrayNode.add(tileName);
        }
        typesNode.set(typeName, arrayNode);
    }

    /**
     * Returns null if there are no unauthorised permissions and an array of unauthorised permissions if there are any
     *
     * @param mapper               to create Json nodes
     * @param connectorPermissions
     * @return as described
     */
    private ArrayNode getUnauthorisedPermissions(ObjectMapper mapper, ConnectorPermissions connectorPermissions) {
        if (connectorPermissions == null) {
            return null;
        }
        ArrayNode unauthorisedPermissions = mapper.createArrayNode();
        for (ConnectorPermission connectorPermission : connectorPermissions.getPermissions()) {
            if (!connectorPermission.isAuthorised()) {
                unauthorisedPermissions.add(PermissionsJsonHelper.toPermission(connectorPermission).toString());
            }
        }
        return unauthorisedPermissions.size() > 0 ? unauthorisedPermissions : null;
    }

    private ConnectorPermissions getConnectorPermissions(String subSystemType) {
        ConnectorPermissions connectorPermissions = null;
        try {
            connectorPermissions = PermissionsJsonHelper.convertJsonToObject(
                    externalPermissionsService.getExternalConnectorPermissionsJson(subSystemType));
        }
        catch (IOException e) {
            log.error("Failed to get unauthorised permissions for connector " + subSystemType, e);
        }
        return connectorPermissions;
    }


    public String getEmailFromSession(HttpSession session) {
        return remoteEnvironmentCallService.getEmailFromSession(session);
    }

    /**
     * Download the addon from the current environment or from a remote one
     *
     * @param session
     * @param authentication
     * @param env
     * @param type
     * @param response
     * @throws IOException
     */
    @RequestMapping(value = "/addon/{type}", method = {RequestMethod.GET})
    public void generateAddon(HttpSession session, Authentication authentication,
                              @RequestParam(value = "env", defaultValue = "sandbox") String env,
                              @PathVariable String type, HttpServletResponse response)
            throws IOException
    {
        if (!RemoteEnvironmentCallService.EnvTypes.isSandbox(env)) {
            String url = JiveUtils
                    .formatUrl(remoteAddonUrl, remoteEnvironmentCallService.getEnvType(env).getServerName(), type);
            remoteEnvironmentCallService.downloadRemoteFile(url, session, authentication, response);
        }
        else {
            writeAddonToResponse(type, response);
        }
    }

    /**
     * Download the connector addon for the current environment
     *
     * @param type
     * @param response
     * @throws IOException
     */
    @RequestMapping(value = "/remote/addon/{type}", method = {RequestMethod.GET})
    public void generateLocalAddon(@PathVariable String type, HttpServletResponse response)
            throws IOException
    {
        writeAddonToResponse(type, response);
    }

    public void writeAddonToResponse(String type, HttpServletResponse response) throws IOException {
        try {
            ExternalConnectorPackageWithEntity externalConnector = externalConnectorPackageInventoryService
                    .getPackageWithEntity(type);
            if (externalConnector == null) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "There is no external connector of type " + type);
                return;
            }
            String fileName =
                    externalConnectorService.getExternalConnectorsPath() + File.separatorChar + type + "-addon.zip";
            File addonZip = generateAddon(type, fileName);
            outputFile(response, addonZip);
            Files.delete(addonZip.toPath());
        }
        catch (Exception e) {
            log.error("Error occurred while generating addon for type" + type, e);
        }
    }

    /**
     * TODO Creates definition also for disabled tiles ??
     *
     * @param systemType
     * @param fileName
     * @return
     * @throws Exception
     */
    private File generateAddon(String systemType, String fileName) throws Exception
    {
        String meta;
        String definition;
        JiveAddon addon;
        ExternalConnectorPackageWithEntity connectorPackage = externalConnectorPackageInventoryService
                .getPackageWithEntity(systemType);
        if (!connectorPackage.isEnabled()) {
            throw new IllegalAccessException("Addons can be generated only for enabled packages");
        }
        AddonDefinition addonDefinition = externalConnectorService
                .getAddonDefinition(connectorPackage.getPackageSystemTypeV2().toString());
        String packageName = connectorPackage.getDisplayName();
        String packageDescription = connectorPackage.getDescription();
        //todo do something with exporter
        List<ExternalConnectorPackageItem> packageItems = connectorPackage.getAllItems();
        if (connectorPackage.isStorage()) {
            JiveTileContainerMap.JiveTileContainer container = jiveTileContainerMap
                    .getByType(connectorPackage.getPackageSystemTypeV2());
            ExternalStorageConnectorConfig storageConfig = (ExternalStorageConnectorConfig) container.tileConfiguration;
            boolean addConfigPlaceResource = storageConfig.isNotEmptyConfigurationClass();
            addon = new StorageAddon(systemType, serverConfigService.getServerURLSSL(),
                    packageDescription, packageName, addConfigPlaceResource,
                    connectorPackage.getMac(), addonDefinition);
        }
        else if (connectorPackage.isExporter()) {
            addon = new ExporterAddon(systemType, serverConfigService.getAddOnUrl(), packageDescription,
                    packageName, connectorPackage.getMac(), addonDefinition);
        }
        else if (connectorPackage.hasStreamIntegration() || connectorPackage.hasTiles()){
            boolean hasStreamIntegration = connectorPackage.hasStreamIntegration();
            Map<String, ExternalConnectorPackageItem> tileMap = new HashMap<>();
            Map<String, TileDescriptor> tileDescriptorMap = new HashMap<>();
            for (ExternalConnectorPackageItem connectorPackageItem : packageItems) {
                if (connectorPackageItem.getType() == ExternalConnectorPackageItem.Type.STREAM_INTEGRATION) {
                    hasStreamIntegration = true;
                }
                else if (connectorPackageItem.getType() == ExternalConnectorPackageItem.Type.TILE) {
                    final String tileName = connectorPackageItem.getTileName();
                    tileMap.put(tileName, connectorPackageItem);
                    final ExternalConnectorService.ExternalTile tile = externalConnectorService
                            .getTile(systemType, tileName);
                    tileDescriptorMap.put(tileName, tile.getTileDescriptor());
                }
            }
            addon = new TileAddon(systemType, serverConfigService.getAddOnUrl(),
                    packageDescription, packageName, connectorPackage.getMac(), connectorPackage.getVersion(), tileMap,
                    hasStreamIntegration, tileDescriptorMap, serverConfigService, addonDefinition);
        } else {
            addon = new AppAddon(systemType, serverConfigService.getAddOnUrl(), packageDescription, packageName,
                    addonDefinition);
        }

        meta = addon.getMetaJson();
        definition = addon.getDefinitionJson();

        File addonZip = new File(fileName);
        FileOutputStream fos = new FileOutputStream(addonZip);
        ZipOutputStream zos = new ZipOutputStream(fos);


        zos.putNextEntry(new ZipEntry("meta.json"));
        IOUtils.write(meta.getBytes(), zos);
        zos.closeEntry();

        zos.putNextEntry(new ZipEntry("definition.json"));
        IOUtils.write(definition.getBytes(), zos);
        zos.closeEntry();

        //Add data folder with icons
        String dataDir =
                externalConnectorService.getExternalConnectorsPath() + File.separatorChar + systemType + "-data";
        File[] dataFiles = new File(dataDir).listFiles();
        zos.putNextEntry(new ZipEntry("data/"));
        zos.closeEntry();
        boolean has16icon = false;
        boolean has48icon = false;
        if (dataFiles != null && dataFiles.length > 0) {
            File curFile;
            for (File dataFile : dataFiles) {
                if (dataFile.isDirectory()) {
                    continue;
                }
                curFile = dataFile;
                zos.putNextEntry(new ZipEntry("data/" + curFile.getName()));
                IOUtils.write(Files.readAllBytes(curFile.toPath()), zos);
                zos.closeEntry();
                if (curFile.getName().toLowerCase().equalsIgnoreCase(ICON_16_PNG)){
                    has16icon = true;
                }
                if (curFile.getName().toLowerCase().equalsIgnoreCase(ICON_48_PNG)){
                    has48icon = true;
                }
            }
        }
        if (!has16icon){
            writeDefaultFileIntoZip("data/"+ICON_16_PNG, zos, 16);
        }
        if (!has48icon){
            writeDefaultFileIntoZip("data/"+ICON_48_PNG, zos, 48);
        }

        //Add public folder for local resources (only if addon/public folder exists in the JAR)
        String jarPathStr =
                externalConnectorService.getExternalConnectorsPath() + File.separatorChar + systemType + ".jar";

        Path jarPath = Paths.get(jarPathStr);

        zipLocalResources(jarPath, zos);

        zos.close();
        fos.close();
        return addonZip;
    }

    /**
     * Put all files under "addon/public" folder in the jar file and place then in the new zip file under the /public folder
     *
     * @param jarPath
     * @throws IOException
     */
    private void zipLocalResources(final Path jarPath, ZipOutputStream zos) throws IOException {
        try (FileSystem fs = FileSystems.newFileSystem(jarPath, null)) {

            String rootFolderName = "/addon/public";
            Files.walkFileTree(fs.getPath(rootFolderName), new SimpleFileVisitor<Path>() {

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    addFileToAddonZip(file);
                    return FileVisitResult.CONTINUE;
                }

                private void addFileToAddonZip(Path file) {
                    try {
                        String content = new String(Files.readAllBytes(file));

                        content = content.replaceAll(ExternalConnectorService.SERVER_URL_PLACEHOLDER, serverConfigService.getServerURLSSL());

                        BufferedInputStream bin = new BufferedInputStream(new ByteArrayInputStream(content.getBytes()));

                        byte[] buf = new byte[8192];
                        int len;

                        //Copy the files to "public" folder in addon zip
                        zos.putNextEntry(new ZipEntry(file.toString().replace("/addon/", "")));
                        while ((len = bin.read(buf)) > 0) {
                            zos.write(buf, 0, len);
                        }
                        zos.closeEntry();
                    }
                    catch (IOException e) {
                        log.error("was unable to save addon public resource from jar " + jarPath + ". resource name:" + file, e);
                    }
                }
            });
        }
        catch (NoSuchFileException e) {
            //do nothing
        }
        catch (Exception e) {
            log.error("unable to create fileSystem object from jar file " + jarPath, e);
        }
    }

    protected boolean writeDefaultFileIntoZip(String zipPath, ZipOutputStream zos, int size) {
        byte[] buf = new byte[1024];
        int len;
        InputStream in;
        in = servletContext.getResourceAsStream("/WEB-INF/jive/extension/streamonce-local/data/stream_" + size + ".png");
        try {
            zos.putNextEntry(new ZipEntry(zipPath));
            while ((len = in.read(buf)) > 0) {
                zos.write(buf, 0, len);
            }
            zos.closeEntry();
            return true;
        }
        catch (IOException e) {

        }
        return false;
    }

    @RequestMapping(value = "/addon/publish/{type}", method = {RequestMethod.GET})
    public String publishAddon(HttpSession session, Authentication authentication, @PathVariable String type,
                               @RequestParam(value = "env", defaultValue = "sandbox") String env,
                               RedirectAttributes redirectAttributes) throws Exception
    {

        RemoteEnvironmentCallService.EnvTypes envType = remoteEnvironmentCallService.getEnvType(env);
        if (envType == null) {
            redirectAttributes.addFlashAttribute("error",
                    "Environment " + env + " is not available. No way to upload addon to registry ");
            return "redirect:/external/connector/manage";
        }
        if (StringUtils.isEmpty(envType.getRegistryUrl()) || StringUtils.isEmpty(envType.getRegistryPwd()) ||
                StringUtils.isEmpty(envType.getRegistryUser()))
        {
            redirectAttributes.addFlashAttribute("error",
                    "Environment " + env +
                            " is not configured. No way to upload addon to registry. One of the configurations is empty ");
            return "redirect:/external/connector/manage";
        }

        String addOnMac = null;
        File addonZip;
        String fileName =
                externalConnectorService.getExternalConnectorsPath() + File.separatorChar + type + "-addon.zip";
        if (!RemoteEnvironmentCallService.EnvTypes.isSandbox(env)) {
            String url = JiveUtils
                    .formatUrl(remoteAddonUrl, remoteEnvironmentCallService.getEnvType(env).getServerName(), type);
            addonZip = remoteEnvironmentCallService.downloadRemoteFile(fileName, url, session, authentication);
            if (addonZip == null) {
                redirectAttributes.addFlashAttribute("error",
                        "Can't read the add-on from the remote machine " + type + " " + env);
                return "redirect:/external/connector/manage";
            }
            url = JiveUtils
                    .formatUrl(remoteAddOnMac, remoteEnvironmentCallService.getEnvType(env).getServerName(), type);
            addOnMac = remoteEnvironmentCallService.getAddOnMac(url, authentication, session);
        }
        else {
            ExternalConnectorPackageWithEntity externalConnector = externalConnectorPackageInventoryService
                    .getPackageWithEntity(type);
            if (externalConnector == null) {
                //response.sendError(HttpServletResponse.SC_NOT_FOUND, "There is no external connector of type " + type);
                redirectAttributes.addFlashAttribute("error",
                        "There is no external connector of type " + type);
                return "redirect:/external/connector/manage";
            }

            if (RemoteEnvironmentCallService.EnvTypes.isSandbox(env)) {
                redirectAttributes.addFlashAttribute("error",
                        "Add on deploy to sandbox is not available " + type);
                return "redirect:/external/connector/manage";
            }

            addonZip = generateAddon(type, fileName);
        }

        /**
         * registry.user=admin
         registry.pwd=jiveapps
         */
        StringBuilder buff = new StringBuilder();
        String mac = registryService
                .uploadAddon(envType.getRegistryUrl(), envType.getRegistryUser(), envType.getRegistryPwd(),
                        addonZip, addonZip.getName(), buff, addOnMac);
        if (mac != null && mac.length() > 0) {
            if (addOnMac == null) {
                if (!RemoteEnvironmentCallService.EnvTypes.isSandbox(env)) {
                    //call remote server to store the add on mac
                    String url = JiveUtils
                            .formatUrl(remoteAddOnMac, remoteEnvironmentCallService.getEnvType(env).getServerName(),
                                    type);
                    String result = remoteEnvironmentCallService.updateAddOnMac(url, authentication, session, mac);
                    if (result == null) {
                        redirectAttributes.addFlashAttribute("error", "Was unable to save add-on mac " + mac);
                        return "redirect:/external/connector/manage";
                    }
                }
                else {
                    ExternalConnectorEntity externalConnector = externalConnectorEntityService.getBySubType(
                            type);
                    //mac was either created or already exist
                    externalConnector.setMac(mac);
                    externalConnectorEntityService.save(externalConnector);
                }
            }
            redirectAttributes.addFlashAttribute("success", "Uploaded addon " + buff.toString());
        }
        else {
            redirectAttributes.addFlashAttribute("error", buff.toString());
        }
        return "redirect:/external/connector/manage";
    }

    @RequestMapping(value = "/remote/macaddon/{connectorType}", method = {RequestMethod.GET})
    @ResponseBody
    public String getAddOnMac(@PathVariable String connectorType) {
        ExternalConnectorPackageWithEntity connectorEntity = externalConnectorPackageInventoryService
                .getPackageWithEntity(
                        connectorType);
        if (connectorEntity == null) {
            return "Error. Connector " + connectorType + " not found";
        }

        try {
            return connectorEntity.getMac();
        }
        catch (Exception e) {
            String message = "Error. Failed to enable connector. " + e.toString();
            log.error(message, e);
            return message;
        }
    }

    @RequestMapping(value = "/remote/macaddon/{connectorType}", method = {RequestMethod.PUT})
    @ResponseBody
    public String updateAddOnMac(@PathVariable String connectorType, @RequestBody String mac) {
        ExternalConnectorEntity connectorEntity = externalConnectorEntityService.getBySubType(connectorType);
        if (connectorEntity == null) {
            log.error("Error. Connector " + connectorType + " not found");
            return ExternalConnectorService.Status.ERROR.toString();
        }

        try {
            if (mac.length() > 0) {
                connectorEntity.setMac(mac);
                externalConnectorEntityService.save(connectorEntity);
            }
            return mac;
        }
        catch (Exception e) {
            String message = "Error. Failed to update add-on mac. " + e.toString();
            log.error(message, e);
            return ExternalConnectorService.Status.ERROR.toString();
        }
    }

    @RequestMapping(value = {"/upload"}, method = RequestMethod.POST)
    public
    @ResponseBody
    ExternalConnectorService.ConnectorRegistrationResponse uploadConnector(HttpServletRequest request,
                                                                                 HttpSession session)
    {
        try {
            CommonsMultipartResolver multipartResolver = new CommonsMultipartResolver();
            MultipartHttpServletRequest multipartRequest = multipartResolver.resolveMultipart(request);

            MultipartFile file = multipartRequest.getFile("file");
            MultipartFile icon16 = multipartRequest.getFile("icon16");
            MultipartFile icon48 = multipartRequest.getFile("icon48");
            MultipartFile icon128 = multipartRequest.getFile("icon128");

            String type = multipartRequest.getParameter("connectorType");
            String connectorClassName = multipartRequest.getParameter("connector");

            if (file != null && StringUtils.isEmpty(type)) {
                log.info(
                        "Loading new connector " + file.getOriginalFilename() + " " + file.getSize() + " bytes");
            }
            else {
                log.info(
                        "Updating connector with type " + type);
            }

            String email = getEmailFromSession(session);
            if (email == null) {
                return new ExternalConnectorService.ConnectorRegistrationResponse(
                        ExternalConnectorService.Status.USER_NOT_LOGGED_IN);
            }

            int maxConnectorsPerUser = externalConnectorService.getMaxConnectorsPerUser();

            //prevent new connectors in sandbox when maximum number of connectors has exceeded
            if (isSdkEndPointEnabled() && maxConnectorsPerUser <= getUserConnectorCountIgnoreDeleted(email) && type == null && !allowedSDKUserService.isAdmin(email)) {
                return new ExternalConnectorService.ConnectorRegistrationResponse(
                        ExternalConnectorService.Status.MAX_CONNECTOR_COUNT_REACHED,
                        "You already have " + maxConnectorsPerUser +
                                " connectors which is the maximum. Delete connectors you no longer need to upload new ones.",
                        true);
            }

            //file can be null only when editing a specific type
            if (file == null && (type == null || type.length() == 0)) {
                return new ExternalConnectorService.ConnectorRegistrationResponse(
                        ExternalConnectorService.Status.MISSING_JAR_FILE);
            }

            if (file != null && !file.getOriginalFilename().toLowerCase().endsWith("jar")) {
                return new ExternalConnectorService.ConnectorRegistrationResponse(
                        ExternalConnectorService.Status.WRONG_FILE_TYPE,
                        file.getOriginalFilename() + " is not a JAR file. Only JAR files can be uploaded", true);
            }

            if ((icon16 != null && !icon16.getContentType().contains("image")) ||
                    (icon48 != null && !icon48.getContentType().contains("image")) ||
                    (icon128 != null && !icon128.getContentType().contains("image")))
            {
                return new ExternalConnectorService.ConnectorRegistrationResponse(
                        ExternalConnectorService.Status.WRONG_FILE_TYPE, "Icons must be image files", true);
            }

            //read binary and save as file
            ExternalConnectorService.ConnectorRegistrationResponse result;
            ExternalJarValidationContext jarValidationContext = null;
            if (file != null) {
                Path path = extractAndSaveLocally(file);
                result = externalConnectorService.registerJar(path, email, false);
                try {
                    if (result.getJarPath() != null) {
                        File jarFile = result.getJarPath().toFile();
                        s3.uploadLocalFileToS3(jarFile);
                        log.info("Jar file [{}] uploaded to S3", jarFile.getAbsolutePath());
                    }
                } catch (Exception e) {
                    log.error("Failed to upload " + path + " to S3", e);
                }

            } else {
                result = new ExternalConnectorService.ConnectorRegistrationResponse(
                        ExternalConnectorService.Status.VALID);
            }

            // Save icons
            saveIconsLocally(icon16, icon48, icon128, type);

            log.info( "Finished with status " +
                    (jarValidationContext == null ? "Valid" : jarValidationContext.getSummary()));

            return result;

        }
        catch (Error | Exception e) {
            log.error("failed uploading connector", e);
            return new ExternalConnectorService.ConnectorRegistrationResponse(
                    ExternalConnectorService.Status.ERROR, e.getMessage());
        }
    }

    private Path saveFileWithFullPath(MultipartFile file, Path path) throws IOException {
        if (Files.notExists(path)) {
            path = Files.createFile(path);
        }
        Files.copy(file.getInputStream(), path, StandardCopyOption.REPLACE_EXISTING);
        return path;
    }

    private Path saveFile(MultipartFile file, Path localPath) throws IOException {
        Path localFile = Paths.get(localPath.toString() + File.separator + file.getOriginalFilename());
        return saveFileWithFullPath(file, localFile);
    }

    private void saveIconsLocally(MultipartFile icon16, MultipartFile icon48, MultipartFile icon128,
                                  String connectorType) throws IOException
    {
        if (icon16 != null || icon48 != null || icon128 != null) {
            String dataDirStr =
                    externalConnectorService.getExternalConnectorsPath() + File.separatorChar + connectorType
                            + "-data";
            File dataDir = new File(dataDirStr);
            if (!dataDir.exists() && !dataDir.mkdir()) {
                log.error("Failed to create data folder for connector " + connectorType);
                return;
            }
            if (icon16 != null) {
                saveFileWithFullPath(icon16, Paths.get(dataDirStr + File.separator + ICON_16_PNG));
            }
            if (icon48 != null) {
                saveFileWithFullPath(icon48, Paths.get(dataDirStr + File.separator + ICON_48_PNG));
            }
            if (icon128 != null) {
                saveFileWithFullPath(icon128, Paths.get(dataDirStr + File.separator + "icon_128.png"));
            }
        }
    }

    private String getBase64EncodedIcon(String connectorType, String iconSize) throws IOException {
        String dataPathStr = externalConnectorService.getExternalConnectorsPath() + File.separatorChar + connectorType
                + "-data";
        if (Files.notExists(Paths.get(dataPathStr))) {
            return null;
        }
        Path iconPath = Paths.get(dataPathStr + File.separatorChar + "icon_" + iconSize + ".png");
        if (Files.exists(iconPath)) {
            return Base64.encodeBase64String(FileUtils.readFileToByteArray(new File(iconPath.toString())));
        }
        return null;
    }

    private Path extractAndSaveLocally(MultipartFile file) throws IOException {
        Path path = Paths.get(externalConnectorService.getExternalConnectorsPath() + "/temp");
        //local folder where all connectors will be saved
        Path localConnectorPath = Files.createDirectories(path);

        if (file.getOriginalFilename().endsWith("jar")) {
            return saveFile(file, localConnectorPath);
        }

        throw new IllegalArgumentException("file is not a jar file") ;
    }

    private void outputFile(HttpServletResponse response, File file) {
        response.setContentLength((int) file.length());
        response.setHeader(CONTENT_DISPOSITION, "attachment; filename=\"" + file.getName() + "\"");

        try (OutputStream out = response.getOutputStream()) {
            IOUtils.copy(new FileInputStream(file), out);
        }
        catch (Exception e) {
            log.error("Failed to copy file");
        }
    }

    @RequestMapping(method = RequestMethod.GET, value = "/manageTeams")
    public String getTeamManagementPage(HttpSession session, Model model, Authentication authentication) {
        boolean isAdmin = remoteEnvironmentCallService.isAdmin(authentication);
        model.addAttribute("tab", "manageTeams");//the tab identifies the content to load in the UI
        ObjectMapper mapper = new ObjectMapper();
        String currentUserEmail = getEmailFromSession(session);
        model.addAttribute("currentUserEmail", currentUserEmail);
        ArrayNode allTeams = convertTeamListToJson(mapper, developmentTeamService.getAllTeams());
        model.addAttribute("allTeams", allTeams);
        model.addAttribute("userTeams", isAdmin ? allTeams : getUserTeams(mapper, currentUserEmail));
        ArrayNode usersJson = mapper.createArrayNode();
        List<AllowedSDKUser> allUserEmails = allowedSDKUserService.getAllUsers();
        for (AllowedSDKUser user : allUserEmails) {
            ObjectNode objectNode = mapper.createObjectNode();
            objectNode.put("id", user.getId());
            objectNode.put("email", user.getEmail());
            objectNode.put("text", user.getEmail());
            usersJson.add(objectNode);
        }
        model.addAttribute("allUsers", usersJson);
        List<ExternalConnectorPackageWithEntity> usersConnectors;
        if (isAdmin) {
            usersConnectors = externalConnectorPackageInventoryService.getAllPackagesWithEntities();
        }
        else {
            usersConnectors = externalConnectorPackageInventoryService.getUserPackagesIncludingTeam(currentUserEmail);
        }
        Map<String, String> connectorToTeamMap = developmentTeamService.getConnectorToTeamMap();
        ArrayNode connectorsJson = mapper.createArrayNode();
        for (ExternalConnectorPackageWithEntity usersConnector : usersConnectors) {
            String subSystemType = usersConnector.getSubSystemType();
            ExternalConnectorPackage connectorPackage = externalConnectorPackageInventoryService
                    .getPackage(subSystemType);
            ObjectNode connector = mapper.createObjectNode();
            connector.put("id", subSystemType);
            connector.put("text", connectorPackage.getDisplayName());
            connector.put("owner", connectorPackage.getOwnerEmail());
            connector.put("team", connectorToTeamMap.get(subSystemType));
            connectorsJson.add(connector);
        }
        model.addAttribute("managedConnectors", connectorsJson);
        model.addAttribute("soServer", serverConfigService.getServerURLSSL());
        return "externalConnector";
    }

    @RequestMapping(method = RequestMethod.GET, value = "/team/{teamId}/data")
    @ResponseBody
    public ObjectNode getTeamMembersAndConnectors(@PathVariable Long teamId) {
        DevelopmentTeam team = developmentTeamService.getTeam(teamId);
        ObjectMapper mapper = new ObjectMapper();
        ArrayNode teamMembersJson = getTeamMembersJson(mapper, team);
        ArrayNode teamConnectorsJson = getTeamConnectorsJson(mapper, team);
        ObjectNode teamJson = mapper.createObjectNode();
        teamJson.set("connectors", teamConnectorsJson);
        teamJson.set("members", teamMembersJson);
        return teamJson;

    }

    @RequestMapping(method = RequestMethod.DELETE, value = "/team/{teamId}")
    @ResponseBody
    public String deleteTeam(@PathVariable Long teamId) {
        try {
            DevelopmentTeam team = developmentTeamService.getTeam(teamId);
            if (team == null) {
                return "Team does not exist";
            }
            if (!team.getConnectors().isEmpty()) {
                StringBuilder connectorList = new StringBuilder("<ul>");
                for (ExternalConnectorEntity connectorEntity : team.getConnectors()) {
                    ExternalConnectorPackage connectorPackage = externalConnectorPackageInventoryService
                            .getPackage(connectorEntity.getSubSystemType());
                    String displayName = connectorPackage.getDisplayName();
                    String owner = connectorPackage.getOwnerEmail();
                    connectorList.append("<li>" + displayName + " owned by " + owner + "</li>");
                }
                connectorList.append("</ul>");
                return "This team is associated with the following connectors and therefore cannot be deleted: " +
                        connectorList;
            }
            developmentTeamService.deleteTeam(teamId);
            return "success";
        }
        catch (Exception e) {
            log.error("Failed to delete team " + teamId, e);
            return "Failed to delete team: " + e.toString();
        }
    }

    @RequestMapping(method = {RequestMethod.PUT, RequestMethod.POST}, value = "/team/members")
    @ResponseBody
    public Map<String, String> updateDevelopmentTeam(HttpServletRequest request,
                                                     @RequestBody DevelopmentTeamUiBean developmentTeamUiBean)
    {
        HashMap<String, String> result = new HashMap<>();
        try {
            Set<String> memberEmailListToSave = developmentTeamUiBean.getMembers();
            Set<String> connectorListToSave = developmentTeamUiBean.getConnectors();
            if (memberEmailListToSave.isEmpty()) {
                result.put("status", "error");
                result.put("errorMessage", "Team cannot be left empty");
                return result;
            }
            List<AllowedSDKUser> memberUsers = allowedSDKUserService.findByEmailInEmails(memberEmailListToSave);
            List<ExternalConnectorEntity> newConnectors = externalConnectorEntityService
                    .getBySubTypes(connectorListToSave);
            if ("POST".equalsIgnoreCase(request.getMethod())) {
                DevelopmentTeam team = new DevelopmentTeam(developmentTeamUiBean.getTeamName());
                team.setMembers(new HashSet<>(memberUsers));
                team.setConnectors(new HashSet<>(newConnectors));
                team.setCreateByEmail(getEmailFromSession(request.getSession()));
                String validationError = validateTeam(team, memberEmailListToSave, connectorListToSave);
                if (validationError == null) {
                    DevelopmentTeam saved = developmentTeamService.save(team);
                    result.put("status", "success");
                    result.put("teamId", saved.getId().toString());
                }
                else {
                    result.put("status", "error");
                    result.put("errorMessage", validationError);
                }
                return result;
            }
            else {
                Long teamId = developmentTeamUiBean.getTeamId();
                DevelopmentTeam team = developmentTeamService.getTeam(teamId);
                if (team == null) {
                    result.put("status", "error");
                    result.put("errorMessage", "Team with ID " + teamId + " does not exist");
                    return result;
                }
                team.setMembers(new HashSet<>(memberUsers));
                team.setConnectors(new HashSet<>(newConnectors));
                String validationError = validateTeam(team, memberEmailListToSave, connectorListToSave);
                if (validationError == null) {
                    DevelopmentTeam saved = developmentTeamService.save(team);
                    result.put("status", "success");
                    result.put("teamId", saved.getId().toString());
                }
                else {
                    result.put("status", "error");
                    result.put("errorMessage", validationError);
                }
                return result;
            }
        }
        catch (Exception e) {
            log.error("Failed to save team " + developmentTeamUiBean, e);
            result.put("status", "error");
            result.put("errorMessage", e.toString());
            return result;
        }
    }

    /**
     * Verifies that a team is ok and returns an error message if not or null if everything's fine
     *
     * @param team
     * @param memberEmailListToSave
     * @param connectorListToSave
     * @return
     */
    private String validateTeam(DevelopmentTeam team, Set<String> memberEmailListToSave,
                                Set<String> connectorListToSave)
    {
        //check that the team is not empty
        Set<AllowedSDKUser> teamMembers = team.getMembers();
        Set<ExternalConnectorEntity> teamConnectors = team.getConnectors();
        if (teamMembers.isEmpty()) {
            return "Team cannot be left empty";
        }
        //make sure there are no unknown team members
        if (memberEmailListToSave.size() > teamMembers.size()) {
            Set<String> unknownUsers = new HashSet<>(memberEmailListToSave);
            //remove existing users to be left with non existing ones
            for (AllowedSDKUser teamMember : teamMembers) {
                unknownUsers.remove(teamMember.getEmail());
            }
            return "User(s) not found: " + unknownUsers;
        }
        //make sure all the connectors really exist
        if (connectorListToSave.size() > teamConnectors.size()) {
            Set<String> unknownConnectorType = new HashSet<>(connectorListToSave);
            //remove existing connectors to be left with non existing ones
            for (ExternalConnectorEntity teamConnector : teamConnectors) {
                unknownConnectorType.remove(teamConnector.getSubSystemType());
            }
            return "Connector(s) not found: " + unknownConnectorType;
        }
        //make sure that for all the connectors in the team, the owner of the connector is part of the team
        for (ExternalConnectorEntity externalConnectorEntity : teamConnectors) {
            ExternalConnectorPackage connectorPackage = externalConnectorPackageInventoryService
                    .getPackage(externalConnectorEntity.getSubSystemType());
            String connectorOwner = connectorPackage.getOwnerEmail();
            if (!memberEmailListToSave.contains(connectorOwner)) {
                return "Team is associated to the connector " + connectorPackage.getDisplayName() +
                        " which is owned by " + connectorOwner + " and therefore that user must be part of the team";
            }
        }
        return null;
    }

    @RequestMapping(value = "/{connectorType}/usage", method = {RequestMethod.GET})
    @ResponseBody
    public String getConnectorUsage(HttpServletRequest request,
                                    @PathVariable String connectorType,
                                    @RequestParam(value = "env", defaultValue = "sandbox") String environment)
    {
        if (!RemoteEnvironmentCallService.EnvTypes.isSandbox(environment)) {
            try {
                String response = remoteEnvironmentCallService
                        .callRemoteContent(null, getEmailFromSession(request.getSession()),
                                false, environment,
                                HttpMethod.GET, remoteUsageUrl, connectorType);
                return response == null ? "Failed to retrieve usage for  " + connectorType + " on environment " +
                        environment : response;
            }
            catch (RestClientException e) {
                String message =
                        "Failed to retrieve usage for  " + connectorType + " on environment " + environment + ". " +
                                e.toString();
                log.error(message, e);
            }
        }
        else {
            ObjectMapper objectMapper = new ObjectMapper();

            try {
                return objectMapper.writeValueAsString(getConnectorUsageLocally(request, connectorType, environment));
            }
            catch (Exception e) {
                log.error("failed to convert response to JSON", e);
            }
        }
        return null;
    }

    @RequestMapping(value = "/remote/{connectorType}/usage", method = {RequestMethod.GET})
    @ResponseBody
    public UsageData getConnectorUsageLocally(HttpServletRequest request,
                                              @PathVariable String connectorType,
                                              @RequestParam(value = "env", defaultValue = "sandbox") String environment)
    {
        ExternalConnectorPackage connectorPackage = externalConnectorPackageInventoryService
                .getPackage(connectorType);
        SystemTypeV2 systemType;
        //small "hack" to allow support for internal connectors as well
        if (connectorPackage != null) {
            systemType = connectorPackage.getPackageSystemTypeV2();
        }
        else {
            systemType = SystemTypeV2.fromString(connectorType);
        }
        return usageService.getUsageDataBySystemType(systemType);
    }

    /**
     * A generic endpoint for remote calls from custom vies to external endpoints
     *
     * @param request
     * @param response
     * @param connectorType
     * @param environment
     * @return
     */
    @RequestMapping(value = "/remotecall/{connectorType}/**", method = {RequestMethod.GET,RequestMethod.POST,RequestMethod.DELETE,RequestMethod.PUT})
    @ResponseBody
    public Object onRemoteCall(HttpServletRequest request,
                               HttpServletResponse response,
                                              @PathVariable String connectorType,
                                              @RequestParam(value = "env", defaultValue = "sandbox") String environment)
    {

        String requestURI = request.getRequestURI();
        String remoteCallStr = "remotecall/" + connectorType;
        String jiveHost = getJiveHost(request);
        String tileId = request.getHeader(INSTANCE_ID_HEADER);

        String espFolderId = request.getParameter(folderId);
        if (StringUtils.isEmpty(tileId) && StringUtils.isNotEmpty(espFolderId)) {
            tileId = espFolderId;
        }

        String internalURI = requestURI.substring(requestURI.indexOf(remoteCallStr) + remoteCallStr.length());
        try {
            Object invokationResponse = externalRequestInvoker.invoke(connectorType, internalURI, request, tileId, jiveHost);

            return invokationResponse;
        }
        catch (Exception e) {
            if (e instanceof HttpStatusCodeException){
                try {
                    response.sendError(((HttpStatusCodeException) e).getStatusCode().value(), ((HttpStatusCodeException) e).getStatusText());
                }
                catch (IOException e1) {
                    throw e;
                }
            }
            return null;
        }
    }

    /**
     * Extract jive host URL from authorization header in ope social API request
     *
     * @param request
     * @return
     */
    private String getJiveHost(HttpServletRequest request) {
        String authz = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authz == null || !authz.startsWith(JIVE_EXTN)) {
            log.warn("Jive authorization isn't properly formatted: " + authz);
            return null;
        }
        Map<String, String> paramsFromAuthz = getParamsFromAuthz(authz);
        String jiveUrl = paramsFromAuthz.get(PARAM_JIVE_URL);
        return JiveUtils.normilizeJiveHost(jiveUrl);
    }

    /**
     * Split an authorizaton string to its parameters
     *
     * @param authz
     * @return
     */
    @Nonnull
    private Map<String, String> getParamsFromAuthz(@Nonnull String authz) {
        if (!authz.startsWith(JIVE_EXTN)) {
            return Maps.newHashMap();
        }

        authz = authz.substring(JIVE_EXTN.length());
        String[] params = authz.split("[?|&]");
        Map<String, String> paramMap = Maps.newHashMap();
        for (String param : params) {
            String[] tokens = param.split("=");
            if (tokens == null || tokens.length != 2) {
                return Maps.newHashMap();
            }

            paramMap.put(decodeUrl(tokens[0]), decodeUrl(tokens[1]));
        }

        return paramMap;
    }

    private String decodeUrl(@Nonnull String url) {
        try {
            return URLDecoder.decode(url, "UTF-8");
        }
        catch (UnsupportedEncodingException e) {
            log.warn("Failed decoding URL using UTF-8 charset", e);
            return url;
        }
    }

}
