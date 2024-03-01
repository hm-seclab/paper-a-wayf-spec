# Testing Documentation

## Setup

- We used the https://github.com/italia/spid-cie-oidc-django testbed implementation that was forked [here](https://github.com/hm-seclab/awayf-spid-cie-oidc-django)
    - Follow the [instructions for the docker compose setup](https://github.com/hm-seclab/awayf-spid-cie-oidc-django?tab=readme-ov-file#docker-compose)
    - No further customizations are necessary
- The example federation consists of the following components:
    - a Trust Anchor (TA): http://ta.a-wayf.local:8000
    - a Relying Party (RP): http://rp.a-wayf.local:8001
    - an OpenID Provider (OP/IdP): http://op.a-wayf.local:8002/oidc/op
- We adjusted the docker-prepare.sh and docker-compose.yaml files according to these domains/entityIds
- We adjusted the source code so the resolve endpoint is publicly accessible and trust chains are generated at each request (without a staff token)
- We mock the enrollment of an appropriate passkey by hard-coding it including the idpId="http://op.a-wayf.local:8002/oidc/op".
- This passkey is stored either:
    1. on a virtual authenticator
    2. or on a Solokey with [modified solo firmware](https://github.com/hm-seclab/awayf-solo1?tab=readme-ov-file#build-locally)
- The client application as well as the virtual authenticator can be found [here](https://github.com/hm-seclab/paper-a-wayf-spec/tree/main/non-browser-poc)

## Scenario

- The OP and SP are run by different organizations
- Both of these organizations are part of the same federation so they both trust the same trust anchor, i.e., TA
- The test user is a member of the organization running the OP
- The user was given an A-WAYF-capable passkey by the IdP beforehand
- The user wants to access the RP
- A-WAYF is triggered by our client application using the terminal, i.e., by executing `./zig-out/bin/client`

## A-WAYF

- Initial Service Access (1):
    - Our client mocks the initial service access normally performed by the user navigating their browser to a federated SP
    - We initiate the A-WAYF process by directly calling resolveWAYF() including the following parameters:
    - idpList=["sso.hm.edu", "idp.orga.edu", "http://op.a-wayf.local:8002/oidc/op"]
    - trust_statements=["eyJhbGciOiJIU...", "eyJhbGciOiJIU...", "eyJhbGciOiJIU..."]
    - protocol="OIDfed"
    - The trust statement is a trust chain, i.e., a list of JWTs, represented by three entity statements:
        - The SP's entity configuration
        - The TA's subordinate statement for the SP
        - The TA's entity configuration
    - As there are no intermediary entities in this setup, there are no further entity statements
- IdP Enumeration (2):
    - Our client calls the CTAP2 authenticatorFederationManagement command to enumerate the idpIds present on the authenticator
    - In case a Solokey is used, the user is prompted to input the PIN.
    - In case our virtual authenticator is used, UV is mocked for simplicity.
    - In our PoC, there is a single appropriate passkey on the authenticator, which has the idpId="http://op.a-wayf.local:8002/oidc/op"
    - This idpId is returned to the client
- IdP Matching (3):
    - Our client matches the idpList received in Step (1) with the idpIds from Step (2)
    - In our PoC, this results in a single candidate IdP with the idpId="http://op.a-wayf.local:8002/oidc/op"
- Trust Resolve (4):
    - The client then issues a request to http://op.a-wayf.local:8002/oidc/op/.well-known/openid-federation
    - The response includeds "federation_resolve_endpoint": "http://op.a-wayf.local:8002/oidc/op/resolve"
    - The subsequent request to resolve the trust is as follows: http://op.a-wayf.local:8002/oidc/op/resolve?sub=http://op.a-wayf.local:8002/oidc/op&anchor=http://ta.a-wayf.local:8000
    - The endpoint responds with a JWT containing the trust chain from the OP to the TA, represented by three entity statements:
        - The OP's entity configuration
        - The TA's subordinate statement for the OP
        - The TA's entity configuration
    - We check the trust chain by verifying the signatures using the public keys in the respective entity configurations
    - Finally, we test whether the TA's public key used for signing the FedSP's trust chain is present in the TA's entity configuration from the OP's trust chain and vice versa
- User Dialog (5):
    - As we only show the IdP's URL without a logo or actual organization name in this PoC, no further requests to the IdP are performed.
    - The user is presented with the remaining candidate IdP, i.e., http://op.a-wayf.local:8002/oidc/op
    - The user chooses the IdP to be used by following the instructions and typing in "0"
- WAYF Response (6):
    - The A-WAYF process is finished and the idpId of the chosen is returned via the command line.
    - As we do not perform actual authentication, the PoC ends here.
