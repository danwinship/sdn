package ranges

import (
	"reflect"
	"testing"
)

func Test_intRange_except(t *testing.T) {
	ranges := []intRange{
		{
			start: newFixedInt(17, 16),
			end:   newFixedInt(135, 16),
		},
	}

	// Note that the tests are cumulative
	for i, tc := range []struct {
		except intRange
		result []intRange
	}{
		{
			except: intRange{
				start: newFixedInt(20, 16),
				end:   newFixedInt(40, 16),
			},

			result: []intRange{
				{
					start: newFixedInt(17, 16),
					end:   newFixedInt(19, 16),
				},
				{
					start: newFixedInt(41, 16),
					end:   newFixedInt(135, 16),
				},
			},
		},
		{
			except: intRange{
				start: newFixedInt(130, 16),
				end:   newFixedInt(140, 16),
			},

			result: []intRange{
				{
					start: newFixedInt(17, 16),
					end:   newFixedInt(19, 16),
				},
				{
					start: newFixedInt(41, 16),
					end:   newFixedInt(129, 16),
				},
			},
		},
		{
			except: intRange{
				start: newFixedInt(100, 16),
				end:   newFixedInt(109, 16),
			},

			result: []intRange{
				{
					start: newFixedInt(17, 16),
					end:   newFixedInt(19, 16),
				},
				{
					start: newFixedInt(41, 16),
					end:   newFixedInt(99, 16),
				},
				{
					start: newFixedInt(110, 16),
					end:   newFixedInt(129, 16),
				},
			},
		},
		{
			except: intRange{
				start: newFixedInt(105, 16),
				end:   newFixedInt(200, 16),
			},

			result: []intRange{
				{
					start: newFixedInt(17, 16),
					end:   newFixedInt(19, 16),
				},
				{
					start: newFixedInt(41, 16),
					end:   newFixedInt(99, 16),
				},
			},
		},
		{
			except: intRange{
				start: newFixedInt(80, 16),
				end:   newFixedInt(99, 16),
			},
			result: []intRange{
				{
					start: newFixedInt(17, 16),
					end:   newFixedInt(19, 16),
				},
				{
					start: newFixedInt(41, 16),
					end:   newFixedInt(79, 16),
				},
			},
		},
		{
			except: intRange{
				start: newFixedInt(100, 16),
				end:   newFixedInt(200, 16),
			},
			result: []intRange{
				{
					start: newFixedInt(17, 16),
					end:   newFixedInt(19, 16),
				},
				{
					start: newFixedInt(41, 16),
					end:   newFixedInt(79, 16),
				},
			},
		},
	} {
		newRanges := []intRange{}
		for _, r := range ranges {
			newRanges = append(newRanges, r.except(tc.except)...)
		}
		ranges = newRanges
		if !reflect.DeepEqual(ranges, tc.result) {
			t.Fatalf("bad result for %d\nexpected %v\ngot      %v", i, tc.result, ranges)
		}
	}
}
