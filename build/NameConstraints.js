"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _GeneralSubtree = require("./GeneralSubtree");

var _GeneralSubtree2 = _interopRequireDefault(_GeneralSubtree);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var NameConstraints = function () {
	//**********************************************************************************
	/**
  * Constructor for NameConstraints class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function NameConstraints() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, NameConstraints);

		//region Internal properties of the object
		if ("permittedSubtrees" in parameters)
			/**
    * @type {Array.<GeneralSubtree>}
    * @description permittedSubtrees
    */
			this.permittedSubtrees = (0, _pvutils.getParametersValue)(parameters, "permittedSubtrees", NameConstraints.defaultValues("permittedSubtrees"));

		if ("excludedSubtrees" in parameters)
			/**
    * @type {Array.<GeneralSubtree>}
    * @description excludedSubtrees
    */
			this.excludedSubtrees = (0, _pvutils.getParametersValue)(parameters, "excludedSubtrees", NameConstraints.defaultValues("excludedSubtrees"));
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


	_createClass(NameConstraints, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, NameConstraints.schema({
				names: {
					permittedSubtrees: "permittedSubtrees",
					excludedSubtrees: "excludedSubtrees"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for NameConstraints");
			//endregion

			//region Get internal properties from parsed schema
			if ("permittedSubtrees" in asn1.result) this.permittedSubtrees = Array.from(asn1.result.permittedSubtrees, function (element) {
				return new _GeneralSubtree2.default({ schema: element });
			});

			if ("excludedSubtrees" in asn1.result) this.excludedSubtrees = Array.from(asn1.result.excludedSubtrees, function (element) {
				return new _GeneralSubtree2.default({ schema: element });
			});
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
			//region Create array for output sequence
			var outputArray = [];

			if ("permittedSubtrees" in this) {
				outputArray.push(new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [new asn1js.Sequence({
						value: Array.from(this.permittedSubtrees, function (element) {
							return element.toSchema();
						})
					})]
				}));
			}

			if ("excludedSubtrees" in this) {
				outputArray.push(new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: [new asn1js.Sequence({
						value: Array.from(this.excludedSubtrees, function (element) {
							return element.toSchema();
						})
					})]
				}));
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

			if ("permittedSubtrees" in this) object.permittedSubtrees = Array.from(this.permittedSubtrees, function (element) {
				return element.toJSON();
			});

			if ("excludedSubtrees" in this) object.excludedSubtrees = Array.from(this.excludedSubtrees, function (element) {
				return element.toJSON();
			});

			return object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "permittedSubtrees":
					return [];
				case "excludedSubtrees":
					return [];
				default:
					throw new Error("Invalid member name for NameConstraints class: " + memberName);
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

			// NameConstraints OID ::= 2.5.29.30
			//
			//NameConstraints ::= SEQUENCE {
			//    permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
			//    excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [permittedSubtrees]
    * @property {string} [excludedSubtrees]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [new asn1js.Repeated({
						name: names.permittedSubtrees || "",
						value: _GeneralSubtree2.default.schema()
					})]
				}), new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: [new asn1js.Repeated({
						name: names.excludedSubtrees || "",
						value: _GeneralSubtree2.default.schema()
					})]
				})]
			});
		}
	}]);

	return NameConstraints;
}();
//**************************************************************************************


exports.default = NameConstraints;
//# sourceMappingURL=NameConstraints.js.map