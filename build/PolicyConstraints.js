"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var PolicyConstraints = function () {
	//**********************************************************************************
	/**
  * Constructor for PolicyConstraints class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function PolicyConstraints() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, PolicyConstraints);

		//region Internal properties of the object
		if ("requireExplicitPolicy" in parameters)
			/**
    * @type {number}
    * @description requireExplicitPolicy
    */
			this.requireExplicitPolicy = (0, _pvutils.getParametersValue)(parameters, "requireExplicitPolicy", PolicyConstraints.defaultValues("requireExplicitPolicy"));

		if ("inhibitPolicyMapping" in parameters)
			/**
    * @type {number}
    * @description Value of the TIME class
    */
			this.inhibitPolicyMapping = (0, _pvutils.getParametersValue)(parameters, "inhibitPolicyMapping", PolicyConstraints.defaultValues("inhibitPolicyMapping"));
		//endregion

		//region If input argument array contains "schema" for this object
		if ("schema" in parameters) this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
  * Return default values for all class members
  * @param {string} memberName String name for a class member
  */


	_createClass(PolicyConstraints, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, PolicyConstraints.schema({
				names: {
					requireExplicitPolicy: "requireExplicitPolicy",
					inhibitPolicyMapping: "inhibitPolicyMapping"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for PolicyConstraints");
			//endregion

			//region Get internal properties from parsed schema
			if ("requireExplicitPolicy" in asn1.result) {
				var field1 = asn1.result.requireExplicitPolicy;

				field1.idBlock.tagClass = 1; // UNIVERSAL
				field1.idBlock.tagNumber = 2; // INTEGER

				var ber1 = field1.toBER(false);
				var int1 = asn1js.fromBER(ber1);

				this.requireExplicitPolicy = int1.result.valueBlock.valueDec;
			}

			if ("inhibitPolicyMapping" in asn1.result) {
				var field2 = asn1.result.inhibitPolicyMapping;

				field2.idBlock.tagClass = 1; // UNIVERSAL
				field2.idBlock.tagNumber = 2; // INTEGER

				var ber2 = field2.toBER(false);
				var int2 = asn1js.fromBER(ber2);

				this.inhibitPolicyMapping = int2.result.valueBlock.valueDec;
			}
			//endregion
		}
		//**********************************************************************************
		/**
   * Convert current object to asn1js object and set correct values
   * @returns {Object} asn1js object
   */

	}, {
		key: "toSchema",
		value: function toSchema() {
			//region Create correct values for output sequence
			var outputArray = [];

			if ("requireExplicitPolicy" in this) {
				var int1 = new asn1js.Integer({ value: this.requireExplicitPolicy });

				int1.idBlock.tagClass = 3; // CONTEXT-SPECIFIC
				int1.idBlock.tagNumber = 0; // [0]

				outputArray.push(int1);
			}

			if ("inhibitPolicyMapping" in this) {
				var int2 = new asn1js.Integer({ value: this.inhibitPolicyMapping });

				int2.idBlock.tagClass = 3; // CONTEXT-SPECIFIC
				int2.idBlock.tagNumber = 1; // [1]

				outputArray.push(int2);
			}
			//endregion

			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				value: outputArray
			});
			//endregion
		}
		//**********************************************************************************
		/**
   * Convertion for the class to JSON object
   * @returns {Object}
   */

	}, {
		key: "toJSON",
		value: function toJSON() {
			var object = {};

			if ("requireExplicitPolicy" in this) object.requireExplicitPolicy = this.requireExplicitPolicy;

			if ("inhibitPolicyMapping" in this) object.inhibitPolicyMapping = this.inhibitPolicyMapping;

			return object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "requireExplicitPolicy":
					return 0;
				case "inhibitPolicyMapping":
					return 0;
				default:
					throw new Error("Invalid member name for PolicyConstraints class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Return value of asn1js schema for current class
   * @param {Object} parameters Input parameters for the schema
   * @returns {Object} asn1js schema object
   */

	}, {
		key: "schema",
		value: function schema() {
			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			// PolicyMappings OID ::= 2.5.29.36
			//
			//PolicyConstraints ::= SEQUENCE {
			//    requireExplicitPolicy           [0] SkipCerts OPTIONAL,
			//    inhibitPolicyMapping            [1] SkipCerts OPTIONAL }
			//
			//SkipCerts ::= INTEGER (0..MAX)

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [requireExplicitPolicy]
    * @property {string} [inhibitPolicyMapping]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.Primitive({
					name: names.requireExplicitPolicy || "",
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					}
				}), // IMPLICIT integer value
				new asn1js.Primitive({
					name: names.inhibitPolicyMapping || "",
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					}
				}) // IMPLICIT integer value
				]
			});
		}
	}]);

	return PolicyConstraints;
}();
//**************************************************************************************


exports.default = PolicyConstraints;
//# sourceMappingURL=PolicyConstraints.js.map