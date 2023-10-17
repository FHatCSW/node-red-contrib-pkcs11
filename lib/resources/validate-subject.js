function isValidSubject(subject) {
        // Check if the subject is an object
        if (typeof subject !== 'object' || subject === null) {
            return false;
        }

        // Check if 'shortName' and 'value' keys are present
        if (!subject.hasOwnProperty('shortName') || !subject.hasOwnProperty('value')) {
            return false;
        }

        // Check if 'shortName' and 'value' are non-empty strings
        if (typeof subject.shortName !== 'string' || typeof subject.value !== 'string') {
            return false;
        }

        // You can add more validation rules here if needed

        return true;
    }

    module.exports = isValidSubject;