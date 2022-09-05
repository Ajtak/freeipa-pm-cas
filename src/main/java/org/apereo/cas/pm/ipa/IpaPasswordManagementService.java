package org.apereo.cas.pm.ipa;

import jdk.jfr.ContentType;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.credential.UsernamePasswordCredential;
import org.apereo.cas.configuration.model.support.pm.PasswordManagementProperties;
import org.apereo.cas.pm.PasswordChangeRequest;
import org.apereo.cas.pm.PasswordHistoryService;
import org.apereo.cas.pm.impl.BasePasswordManagementService;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.util.crypto.CipherExecutor;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.Serializable;
import java.util.Objects;


public class IpaPasswordManagementService extends BasePasswordManagementService {
    private final RestTemplate restTemplate;

    public IpaPasswordManagementService(final CipherExecutor<Serializable, String> cipherExecutor,
                                         final String issuer,
                                         final RestTemplate restTemplate,
                                         final PasswordManagementProperties passwordManagementProperties,
                                         final PasswordHistoryService passwordHistoryService) {
        super(passwordManagementProperties, cipherExecutor, issuer, passwordHistoryService);
        this.restTemplate = restTemplate;
    }

    @Override
    public boolean changeInternal(final Credential credential, final PasswordChangeRequest bean) {
        val rest = properties.getRest();

        if (StringUtils.isBlank(rest.getEndpointUrlChange())) {
            return false;
        }

        val upc = (UsernamePasswordCredential) credential;
        val headers = new HttpHeaders();
        headers.setAccept(CollectionUtils.wrap(MediaType.APPLICATION_JSON));

        val body = new LinkedMultiValueMap<>();
        body.put("user", CollectionUtils.wrap(upc.getUsername()));
        body.put("old_password", CollectionUtils.wrap(bean.getPassword()));
        body.put("new_password", CollectionUtils.wrap(upc.getPassword()));

        val entity = new HttpEntity<>(body, headers);
        val result = restTemplate.exchange(rest.getEndpointUrlChange(), HttpMethod.POST, entity, Boolean.class);
        return result.getStatusCodeValue() == HttpStatus.OK.value() && result.hasBody()
                && Objects.requireNonNull(result.getBody());
    }

}
