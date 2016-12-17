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

var BasicConstraints = function () {
	//**********************************************************************************
	/**
  * Constructor for TIME class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  * @property {Object} [cA]
  * @property {Object} [pathLenConstraint]
  */

	function BasicConstraints() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, BasicConstraints);

		//region Internal properties of the object
		/**
   * @type {boolean}
   * @description cA
   */
		this.cA = (0, _pvutils.getParametersValue)(parameters, "cA", false);

		if ("pathLenConstraint" in parameters)
			/**
    * @type {number|Integer}
    * @description pathLenConstraint
    */
			this.pathLenConstraint = (0, _pvutils.getParametersValue)(parameters, "pathLenConstraint", 0);
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


	_createClass(BasicConstraints, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, BasicConstraints.schema({
				names: {
					cA: "cA",
					pathLenConstraint: "pathLenConstraint"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for BasicConstraints");
			//endregion

			//region Get internal properties from parsed schema
			if ("cA" in asn1.result) this.cA = asn1.result.cA.valueBlock.value;

			if ("pathLenConstraint" in asn1.result) {
				if (asn1.result.pathLenConstraint.valueBlock.isHexOnly) this.pathLenConstraint = asn1.result.pathLenConstraint;else this.pathLenConstraint = asn1.result.pathLenConstraint.valueBlock.valueDec;
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
			//region Create array for output sequence
			var outputArray = [];

			if (this.cA !== BasicConstraints.defaultValues("cA")) outputArray.push(new asn1js.Boolean({ value: this.cA }));

			if ("pathLenConstraint" in this) {
				if (this.pathLenConstraint instanceof asn1js.Integer) outputArray.push(this.pathLenConstraint);else outputArray.push(new asn1js.Integer({ value: this.pathLenConstraint }));
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

			if (this.cA !== BasicConstraints.defaultValues("cA")) object.cA = this.cA;

			if ("pathLenConstraint" in this) {
				if (this.pathLenConstraint instanceof asn1js.Integer) object.pathLenConstraint = this.pathLenConstraint.toJSON();else object.pathLenConstraint = this.pathLenConstraint;
			}

			return object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "cA":
					return false;
				default:
					throw new Error("Invalid member name for BasicConstraints class: " + memberName);
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

			// BasicConstraints OID ::= 2.5.29.19
			//
			//BasicConstraints ::= SEQUENCE {
			//    cA                      BOOLEAN DEFAULT FALSE,
			//    pathLenConstraint       INTEGER (0..MAX) OPTIONAL }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [cA]
    * @property {string} [pathLenConstraint]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.Boolean({
					optional: true,
					name: names.cA || ""
				}), new asn1js.Integer({
					optional: true,
					name: names.pathLenConstraint || ""
				})]
			});
		}
	}]);

	return BasicConstraints;
}();
//**************************************************************************************


exports.default = BasicConstraints;
//# sourceMappingURL=BasicConstraints.js.map