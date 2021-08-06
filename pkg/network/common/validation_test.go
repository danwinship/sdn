package common

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	osdnv1 "github.com/openshift/api/network/v1"
)

func TestValidateHostSubnet(t *testing.T) {
	tests := []struct {
		name           string
		hs             *osdnv1.HostSubnet
		expectedErrors int
	}{
		{
			name: "good",
			hs: &osdnv1.HostSubnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "abc.def.com",
				},
				Host:   "abc.def.com",
				HostIP: "10.20.30.40",
				Subnet: "8.8.8.0/24",
			},
			expectedErrors: 0,
		},
		{
			name: "missing subnet",
			hs: &osdnv1.HostSubnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "abc.def.com",
				},
				Host:   "abc.def.com",
				HostIP: "10.20.30.40",
			},
			expectedErrors: 1,
		},
		{
			name: "missing subnet plus annotation",
			hs: &osdnv1.HostSubnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "abc.def.com",
					Annotations: map[string]string{
						"pod.network.openshift.io/assign-subnet": "true",
					},
				},
				Host:   "abc.def.com",
				HostIP: "10.20.30.40",
			},
			expectedErrors: 0,
		},
	}

	for _, tc := range tests {
		err := ValidateHostSubnet(tc.hs)

		if err == nil && tc.expectedErrors > 0 {
			t.Errorf("Test case %s expected errors, but passed", tc.name)
		} else if err != nil && tc.expectedErrors == 0 {
			t.Errorf("Test case %s expected no error, got %v", tc.name, err)
		}
	}
}
