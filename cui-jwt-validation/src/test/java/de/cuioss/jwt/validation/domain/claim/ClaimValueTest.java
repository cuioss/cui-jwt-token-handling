/**
 * Copyright © 2025 CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.jwt.validation.domain.claim;

import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.OffsetDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("Tests ClaimValue functionality")
class ClaimValueTest {

    private static final String TEST_STRING = "test-value";
    private static final OffsetDateTime TEST_DATE = OffsetDateTime.now();

    @Test
    @DisplayName("Should create ClaimValue for plain string")
    void shouldCreateForPlainString() {
        // Given, When
        ClaimValue value = ClaimValue.forPlainString(TEST_STRING);

        // Then
        assertEquals(TEST_STRING, value.getOriginalString());
        assertEquals(ClaimValueType.STRING, value.getType());
        assertTrue(value.getAsList().isEmpty());
        assertNull(value.getDateTime());
        assertTrue(value.isPresent());
        assertFalse(value.isEmpty());
    }

    @Test
    @DisplayName("Should create ClaimValue for sorted set")
    void shouldCreateForSortedSet() {
        // Given
        SortedSet<String> set = new TreeSet<>(Arrays.asList("value1", "value2", "value3"));
        List<String> expectedList = new ArrayList<>(set);

        // When
        ClaimValue value = ClaimValue.forSortedSet(TEST_STRING, set);

        // Then
        assertEquals(TEST_STRING, value.getOriginalString());
        assertEquals(ClaimValueType.STRING_LIST, value.getType());
        assertEquals(expectedList, value.getAsList());
        assertNull(value.getDateTime());
        assertTrue(value.isPresent());
        assertFalse(value.isEmpty());
    }

    @Test
    @DisplayName("Should create ClaimValue for list")
    void shouldCreateForList() {
        // Given
        List<String> list = Arrays.asList("value1", "value2", "value3");

        // When
        ClaimValue value = ClaimValue.forList(TEST_STRING, list);

        // Then
        assertEquals(TEST_STRING, value.getOriginalString());
        assertEquals(ClaimValueType.STRING_LIST, value.getType());
        assertEquals(list, value.getAsList());
        assertNull(value.getDateTime());
        assertTrue(value.isPresent());
        assertFalse(value.isEmpty());
    }

    @Test
    @DisplayName("Should create ClaimValue for date time")
    void shouldCreateForDateTime() {
        // Given, When
        ClaimValue value = ClaimValue.forDateTime(TEST_STRING, TEST_DATE);

        // Then
        assertEquals(TEST_STRING, value.getOriginalString());
        assertEquals(ClaimValueType.DATETIME, value.getType());
        assertTrue(value.getAsList().isEmpty());
        assertEquals(TEST_DATE, value.getDateTime());
        assertTrue(value.isPresent());
        assertFalse(value.isEmpty());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t", "\n"})
    @DisplayName("Should handle null and empty strings")
    void shouldHandleNullAndEmptyStrings(String input) {
        // Given, When
        ClaimValue value = ClaimValue.forPlainString(input);

        // Then
        assertEquals(input, value.getOriginalString());
        if (input == null) {
            assertTrue(value.isEmpty());
            assertFalse(value.isPresent());
        } else {
            assertFalse(value.isEmpty());
            assertTrue(value.isPresent());
        }
    }

    @Test
    @DisplayName("Should create default claim values")
    void shouldCreateEmptyClaimValues() {
        // Given, When, Then
        ClaimValue stringValue = ClaimValue.createEmptyClaimValue(ClaimValueType.STRING);
        assertNull(stringValue.getOriginalString());
        assertEquals(ClaimValueType.STRING, stringValue.getType());

        ClaimValue listValue = ClaimValue.createEmptyClaimValue(ClaimValueType.STRING_LIST);
        assertNull(listValue.getOriginalString());
        assertEquals(ClaimValueType.STRING_LIST, listValue.getType());
        assertTrue(listValue.getAsList().isEmpty());

        ClaimValue dateTimeValue = ClaimValue.createEmptyClaimValue(ClaimValueType.DATETIME);
        assertNull(dateTimeValue.getOriginalString());
        assertEquals(ClaimValueType.DATETIME, dateTimeValue.getType());
        assertNull(dateTimeValue.getDateTime());
    }

    @Test
    @DisplayName("Should check if value is present for claim value type")
    void shouldCheckIfValueIsPresentForClaimValueType() {
        // Given
        ClaimValue presentString = ClaimValue.forPlainString(TEST_STRING);
        ClaimValue nullString = ClaimValue.forPlainString(null);

        SortedSet<String> nonEmptySet = new TreeSet<>(Set.of("value"));
        ClaimValue nonEmptySetValue = ClaimValue.forSortedSet("original", nonEmptySet);

        List<String> emptyList = Collections.emptyList();
        List<String> nonEmptyList = List.of("value");
        ClaimValue emptyListValue = ClaimValue.forList(null, emptyList);
        ClaimValue nonEmptyListValue = ClaimValue.forList("original", nonEmptyList);

        ClaimValue nullDateTime = ClaimValue.forDateTime(null, null);
        ClaimValue nonNullDateTime = ClaimValue.forDateTime("original", TEST_DATE);

        // When, Then
        // If originalString is present and it's a STRING type, it's present for its type
        assertFalse(presentString.isNotPresentForClaimValueType());

        // For null originalString, it's not present for any type
        assertTrue(nullString.isNotPresentForClaimValueType()); // STRING type returns true when originalString is null

        assertFalse(nonEmptySetValue.isNotPresentForClaimValueType()); // Non-empty set converted to list returns false

        assertTrue(emptyListValue.isNotPresentForClaimValueType()); // Empty list returns true
        assertFalse(nonEmptyListValue.isNotPresentForClaimValueType()); // Non-empty list returns false

        assertTrue(nullDateTime.isNotPresentForClaimValueType()); // Null datetime returns true
        assertFalse(nonNullDateTime.isNotPresentForClaimValueType()); // Non-null datetime returns false
    }

    @Test
    @DisplayName("Should throw NullPointerException for null claim value type")
    void shouldThrowExceptionForNullType() {
        // Given
        ClaimValueType nullType = null;

        // When, Then
        assertThrows(NullPointerException.class, () -> {
            ClaimValue.createEmptyClaimValue(nullType);
        }, "Should throw NullPointerException when null is passed to createEmptyClaimValue");
    }
}