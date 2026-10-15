#include <cassert>

#include "ack_state.h"

int main() {
  const char *device = "SolarGuard-01";
  const char *current = "boot1234-2";
  const char *completed = "boot1234-1";

  assert(classifyTelemetryAcknowledgement(
             device, current, "stored", false, device, true, current, completed
         ) == AckDisposition::STORED);
  assert(classifyTelemetryAcknowledgement(
             device, current, "stored", true, device, true, current, completed
         ) == AckDisposition::DUPLICATE_STORED);
  assert(classifyTelemetryAcknowledgement(
             device, completed, "stored", true, device, true, current, completed
         ) == AckDisposition::REPEATED_COMPLETED_MESSAGE);
  assert(classifyTelemetryAcknowledgement(
             device, "unrelated-id", "stored", false, device, true, current, completed
         ) == AckDisposition::WRONG_MESSAGE_ID);
  assert(classifyTelemetryAcknowledgement(
             "Other-Device", current, "stored", false, device, true, current, completed
         ) == AckDisposition::WRONG_DEVICE);
  assert(classifyTelemetryAcknowledgement(
             device, current, "retry", false, device, true, current, completed
         ) == AckDisposition::RETRY);
  assert(classifyTelemetryAcknowledgement(
             device, current, "error", false, device, true, current, completed
         ) == AckDisposition::RETRY);
  assert(classifyTelemetryAcknowledgement(
             device, current, "rejected", false, device, true, current, completed
         ) == AckDisposition::REJECTED);
  assert(classifyTelemetryAcknowledgement(
             device, current, "stored", false, device, false, nullptr, current
         ) == AckDisposition::REPEATED_COMPLETED_MESSAGE);
  assert(classifyTelemetryAcknowledgement(
             device, current, "unexpected", false, device, true, current, completed
         ) == AckDisposition::UNKNOWN_OUTCOME);
  assert(classifyTelemetryAcknowledgement(
             device, current, "retry", true, device, true, current, completed
         ) == AckDisposition::MALFORMED);
}
