
#pragma once

#include <cstring>

enum class AckDisposition {
  MALFORMED,
  WRONG_DEVICE,
  NO_PENDING_MESSAGE,
  WRONG_MESSAGE_ID,
  REPEATED_COMPLETED_MESSAGE,
  STORED,
  DUPLICATE_STORED,
  REJECTED,
  RETRY,
  UNKNOWN_OUTCOME,
};

inline AckDisposition classifyTelemetryAcknowledgement(
    const char *acknowledgedDevice,
    const char *acknowledgedId,
    const char *outcome,
    bool duplicate,
    const char *expectedDevice,
    bool hasPendingMessage,
    const char *pendingMessageId,
    const char *lastCompletedMessageId
) {
  if (acknowledgedDevice == nullptr ||
      acknowledgedId == nullptr ||
      outcome == nullptr ||
      expectedDevice == nullptr) {
    return AckDisposition::MALFORMED;
  }

  if (std::strcmp(acknowledgedDevice, expectedDevice) != 0) {
    return AckDisposition::WRONG_DEVICE;
  }

  if (!hasPendingMessage || pendingMessageId == nullptr) {
    return lastCompletedMessageId != nullptr &&
                   std::strcmp(acknowledgedId, lastCompletedMessageId) == 0
               ? AckDisposition::REPEATED_COMPLETED_MESSAGE
               : AckDisposition::NO_PENDING_MESSAGE;
  }

  if (std::strcmp(acknowledgedId, pendingMessageId) != 0) {
    return lastCompletedMessageId != nullptr &&
                   std::strcmp(acknowledgedId, lastCompletedMessageId) == 0
               ? AckDisposition::REPEATED_COMPLETED_MESSAGE
               : AckDisposition::WRONG_MESSAGE_ID;
  }

  if (std::strcmp(outcome, "stored") == 0) {
    return duplicate
               ? AckDisposition::DUPLICATE_STORED
               : AckDisposition::STORED;
  }

  if (duplicate) {
    return AckDisposition::MALFORMED;
  }

  if (std::strcmp(outcome, "rejected") == 0) {
    return AckDisposition::REJECTED;
  }

  if (std::strcmp(outcome, "retry") == 0 ||
      std::strcmp(outcome, "error") == 0) {
    return AckDisposition::RETRY;
  }

  return AckDisposition::UNKNOWN_OUTCOME;
}
