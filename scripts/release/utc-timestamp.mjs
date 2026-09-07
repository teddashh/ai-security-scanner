const UTC_TIMESTAMP_PATTERN =
  /^([0-9]{4})-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])(?:\.([0-9]{1,9}))?(Z|\+00:00)$/u;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

export function canonicalUtcTimestampOrderKey(value, label) {
  assert(typeof value === "string" && value.length <= 64, `${label} must be a bounded timestamp`);
  const match = value.match(UTC_TIMESTAMP_PATTERN);
  assert(match, `${label} is not a canonical UTC timestamp`);
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fraction = ""] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  assert(year >= 2000, `${label} is outside the supported UTC range`);

  const epochMilliseconds = Date.UTC(year, month - 1, day, hour, minute, second);
  const instant = new Date(epochMilliseconds);
  assert(
    instant.getUTCFullYear() === year
      && instant.getUTCMonth() === month - 1
      && instant.getUTCDate() === day
      && instant.getUTCHours() === hour
      && instant.getUTCMinutes() === minute
      && instant.getUTCSeconds() === second,
    `${label} is not a real UTC instant`,
  );

  const nanoseconds = BigInt(fraction.padEnd(9, "0"));
  return BigInt(Math.trunc(epochMilliseconds / 1000)) * 1_000_000_000n + nanoseconds;
}
