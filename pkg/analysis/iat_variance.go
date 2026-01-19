// Lophiid distributed honeypot
// Copyright (C) 2026 Niels Heinen
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
package analysis

import (
	"fmt"
	"math"
)

const minimumGapsRequired = 4
const minimumMeanGapSeconds = 0.0001 // 0.1ms - treat anything below as instant
const burstThresholdSeconds = 1.0    // Gaps below this are considered part of a burst

type BehaviorProfile struct {
	OverallCV float64
	HasBursts bool
}

func (p *BehaviorProfile) IsHuman() bool {
	return p.OverallCV > 1.0
}

// CalculateCoefficientOfVariation returns the coefficient of variation for a given set of inter-arrival times.
// Returns a float which means:
//
//	CV < 0.5  :: Highly Rhythmic (Scripted/Bot)
//	CV ~ 1.0  :: Random (Sophisticated Bot)
//	CV > 1.0  :: Bursty/Chaotic (Likely Human)
func CalculateCoefficientOfVariation(gaps []float64) (float64, error) {
	if len(gaps) < minimumGapsRequired {
		return 0, fmt.Errorf("not enough data to calculate CV")
	}

	var sum float64
	for _, gap := range gaps {
		if gap < 0 {
			return 0, fmt.Errorf("negative gap detected")
		}
		sum += gap
	}
	mean := sum / float64(len(gaps))

	// Guard against divide-by-zero or negative gaps.
	// If mean is effectively 0, it's a script blasting requests instantly.
	if mean <= minimumMeanGapSeconds {
		return 0, nil
	}

	// Calculate Variance
	var varianceSum float64
	for _, gap := range gaps {
		diff := gap - mean
		varianceSum += (diff * diff)
	}

	// Standard Deviation = Sqrt(Variance)
	// Note: We use population variance logic here (dividing by N) rather than sample (N-1)
	// because we are analyzing the specific set of observed gaps, not inferring a larger population.
	stdev := math.Sqrt(varianceSum / float64(len(gaps)))

	// Calculate Coefficient of Variation (CV)
	cv := stdev / mean
	return cv, nil
}

// GroupBurstGaps collapses consecutive gaps below the threshold into a single averaged gap.
// Gaps at or above the threshold are passed through unchanged.
// This helps eliminate browser-automated request patterns and focus on human think-time.
func GroupBurstGaps(gaps []float64, threshold float64) []float64 {
	if len(gaps) == 0 {
		return []float64{}
	}

	var result []float64
	var burstSum float64
	var burstCount int

	for _, gap := range gaps {
		if gap < threshold {
			// Accumulate burst gaps
			burstSum += gap
			burstCount++
		} else {
			// End of burst - add averaged burst if any
			if burstCount > 0 {
				result = append(result, burstSum/float64(burstCount))
				burstSum = 0
				burstCount = 0
			}
			// Add the non-burst gap
			result = append(result, gap)
		}
	}

	// Handle remaining burst at the end
	if burstCount > 0 {
		result = append(result, burstSum/float64(burstCount))
	}

	return result
}

func GetSessionBehaviorProfile(gaps []float64) (BehaviorProfile, error) {
	nonBurstGaps := GroupBurstGaps(gaps, burstThresholdSeconds)

	retVal := BehaviorProfile{}
	retVal.HasBursts = len(nonBurstGaps) < len(gaps)

	cv, err := CalculateCoefficientOfVariation(nonBurstGaps)
	if err != nil {
		return BehaviorProfile{}, err
	}

	retVal.OverallCV = cv
	return retVal, nil
}
