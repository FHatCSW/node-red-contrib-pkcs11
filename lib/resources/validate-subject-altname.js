    function isValidSubjectAlternativeName(san) {
        // Check if the SAN is an object
        if (typeof san !== 'object' || san === null) {
            return false;
        }

        // Check if 'type' key is present and has a valid value
        if (!san.hasOwnProperty('type') || typeof san.type !== 'number') {
            return false;
        }

        // Check if 'value' or 'ip' key is present based on 'type' value
        if (
            (san.type === 2 || san.type === 6) &&
            (!san.hasOwnProperty('value') || typeof san.value !== 'string')
        ) {
            return false;
        }

        if (san.type === 7 && (!san.hasOwnProperty('ip') || typeof san.ip !== 'string')) {
            return false;
        }

        // You can add more validation rules here if needed

        return true;
    }

        module.exports = isValidSubjectAlternativeName;
