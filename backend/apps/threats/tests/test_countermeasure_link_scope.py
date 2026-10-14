"""Linking a countermeasure may only reach threats of its own threat model.

``link`` used to look the threat up by id alone. A user with write access in one
organization could attach a countermeasure to a threat in another organization and
have that threat's status recalculated.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import Orgsystem, OrgsystemComponent
from apps.threat_models.models import ThreatModel, ThreatModelOrgsystem
from apps.threats.models import (
    ComponentInstanceThreat,
    InstanceCountermeasure,
)

User = get_user_model()


class CountermeasureLinkScopeTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            username="analyst", email="analyst@a.test", password="pw"
        )
        cls.org_a = Organization.objects.create(name="Org A")
        cls.org_b = Organization.objects.create(name="Org B")
        OrganizationMember.objects.create(
            organization=cls.org_a, user=cls.user, role="security_team"
        )

        cls.tm_a = ThreatModel.objects.create(
            organization=cls.org_a, created_by=cls.user, name="TM A"
        )
        cls.tm_b = ThreatModel.objects.create(
            organization=cls.org_b, created_by=cls.user, name="TM B"
        )

        # A threat in org B, on a component of an orgsystem associated with TM B.
        system_b = Orgsystem.objects.create(organization=cls.org_b, name="System B")
        ThreatModelOrgsystem.objects.create(threat_model=cls.tm_b, orgsystem=system_b)
        component_b = OrgsystemComponent.objects.create(
            orgsystem=system_b, name="Component B"
        )
        cls.foreign_threat = ComponentInstanceThreat.objects.create(
            component=component_b, inherent_severity="high"
        )

        # A threat in org A, on a component of an orgsystem associated with TM A.
        system_a = Orgsystem.objects.create(organization=cls.org_a, name="System A")
        ThreatModelOrgsystem.objects.create(threat_model=cls.tm_a, orgsystem=system_a)
        component_a = OrgsystemComponent.objects.create(
            orgsystem=system_a, name="Component A"
        )
        cls.own_threat = ComponentInstanceThreat.objects.create(
            component=component_a, inherent_severity="high"
        )

        cls.countermeasure = InstanceCountermeasure.objects.create(
            threat_model=cls.tm_a, countermeasure_name="Patch management"
        )

    def setUp(self):
        self.client = APIClient()
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(self.user).access_token}"
        )
        self.url = f"/api/countermeasures/{self.countermeasure.pk}/link/"

    def test_cannot_link_threat_from_another_organization(self):
        response = self.client.post(
            self.url,
            {"threat_id": self.foreign_threat.pk, "threat_type": "component"},
            format="json",
        )

        self.assertEqual(response.status_code, 404)
        self.assertFalse(
            self.countermeasure.threat_links.filter(
                component_threat=self.foreign_threat
            ).exists()
        )

    def test_can_link_threat_of_the_same_threat_model(self):
        response = self.client.post(
            self.url,
            {"threat_id": self.own_threat.pk, "threat_type": "component"},
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        self.assertTrue(
            self.countermeasure.threat_links.filter(
                component_threat=self.own_threat
            ).exists()
        )
